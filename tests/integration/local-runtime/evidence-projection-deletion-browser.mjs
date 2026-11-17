import assert from 'node:assert/strict';
import { execFile, execFileSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { access, chmod, mkdir, readFile, realpath, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import { Pool } from 'pg';
import { expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import {
  governThroughWorkbench,
  readWorkbenchApproval,
  withTransactionBrowser,
  workbenchInputFields,
  openEvidenceRecordActions,
} from './transaction-workbench-browser.mjs';
import { publicEvidenceReader } from './evidence-rejection-deletion-checks.mjs';
import {
  transactionCandidate,
  transactionOperation,
} from '../../../apps/admin-web/app/api/v1/ui/transaction-workbench-contract.ts';
import {
  transactionForms,
  transactionFields,
} from '../../../apps/admin-web/lib/transaction-workflow.ts';
import { projectionDeletionPlan } from '../../../services/control-api/src/evidence/projection-deletion-contracts.ts';
import { localEvidenceDeletionPlan } from '../../../services/control-api/src/evidence/deletion-contracts.ts';
import { LocalEvidenceVault } from '../../../services/control-api/src/evidence/local-vault.ts';
import {
  verifyReceiptCose,
  decodeAdmittedReceipt,
} from '../../../packages/security-kernel/src/index.ts';
import { uuidv7 } from '../../../services/control-api/src/configuration/governed-mutation-http.ts';
import {
  rpcProjectionRetirementBrowser,
  rpcDenialRetirementBrowser,
  rpcDenialRetirementInput,
  rpcRetirementPolicyCases,
  rpcRetirementPolicyFields,
  rpcTerminalRemainderBrowser,
  rpcTerminalResumeInputs,
} from './evidence-rpc-retirement-browser.mjs';
import { factProjectionRetirementBrowser } from './evidence-fact-retirement-browser.mjs';
import { retentionSearchProjectionBrowser } from './evidence-retention-search-browser.mjs';
import { deploymentProjectionRetirementBrowser } from './evidence-deployment-retirement-browser.mjs';
import {
  rpcPayloadRetirementInputs,
  rpcPayloadRetirementReadbackInputs,
  rpcPayloadSearchRetirementBrowser,
} from './evidence-rpc-payload-retirement-browser.mjs';

const exec = promisify(execFile);
const urn = (id) => `urn:openpc:resource:${id}`;
const endpoint = '/api/v1/ui/evidence-workbench';
const foreignPrivacy = (privacy) =>
  privacy === '018f0000-0000-7000-8000-000000000201'
    ? '018f0000-0000-7000-8000-000000006201'
    : '018f0000-0000-7000-8000-000000000201';
const policyFields = (dataClass) => ({
  'Retained data class': dataClass,
  'Retention policy version': '1.0.0',
  'Retention period in milliseconds': '0',
  'Local grace in milliseconds': '0',
  'Required durable sink acknowledgements': '1',
  'Deletion mode': dataClass === 'AUDIT_EVIDENCE' ? 'ROW_DELETE' : 'PROJECTION_DELETE',
  'Require independent deletion approval': 'true',
});

const hash = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const digestPattern = /^sha256:[0-9a-f]{64}$/u;
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

export function authenticationResumeInputs(input) {
  assert.ok(input && typeof input === 'object' && !Array.isArray(input));
  assert.deepEqual(Object.keys(input).sort(), [
    'actorsDigest',
    'checkpoints',
    'keyDigests',
    'records',
    'trust',
    'workerDigest',
    'workerRoot',
  ]);
  assert.equal(resolve(input.workerRoot), input.workerRoot);
  for (const value of [input.workerDigest, input.actorsDigest]) assert.match(value, digestPattern);
  assert.equal(Object.keys(input.keyDigests).length, 1);
  for (const [file, digest] of Object.entries(input.keyDigests)) {
    assert.equal(resolve(file), file);
    assert.match(digest, digestPattern);
  }
  assert.equal(input.records.length, 2);
  for (const [index, record] of input.records.entries()) {
    assert.deepEqual(Object.keys(record).sort(), [
      'id',
      'receipt_digest',
      'record_id',
      'segment_id',
      'sequence',
    ]);
    for (const value of [record.id, record.record_id, record.segment_id])
      assert.match(value, uuidPattern);
    assert.match(record.receipt_digest, digestPattern);
    assert.match(record.sequence, /^[1-9][0-9]*$/u);
    assert.ok(BigInt(record.sequence) <= 18446744073709551615n);
    if (index) {
      assert.ok(record.record_id > input.records[index - 1].record_id);
      assert.ok(BigInt(record.sequence) > BigInt(input.records[index - 1].sequence));
    }
  }
  assert.equal(new Set(input.records.map((r) => r.id)).size, 2);
  assert.ok(Array.isArray(input.checkpoints) && input.checkpoints.length);
  assert.ok(Array.isArray(input.trust) && input.trust.length);
  return input;
}

export function authenticationResumePolicies(policies) {
  assert.equal(policies.length, 5);
  const search = policies.filter((p) => p.dataClass === 'SEARCH_PROJECTION');
  const normalized = policies
    .filter((p) => p.dataClass === 'NORMALIZED_JSON_PROJECTION')
    .sort((a, b) => a.policyVersion.localeCompare(b.policyVersion));
  assert.equal(search.length, 1);
  assert.equal(normalized.length, 4);
  const first = { version: '1.0.0', period: '0', grace: '0', quorum: '1' };
  for (const [index, policy] of [search[0], ...normalized].entries()) {
    const value = index <= 1 ? first : rpcRetirementPolicyCases[index - 2];
    assert.equal(policy.policyVersion, value.version);
    assert.equal(policy.state, index === 0 || index === 4 ? 'ACTIVE' : 'RETIRED');
    assert.equal(policy.retentionPeriodMs, value.period);
    assert.equal(policy.localGraceMs, value.grace);
    assert.equal(policy.sinkQuorum, Number(value.quorum));
    assert.equal(policy.deletionMode, 'PROJECTION_DELETE');
    assert.equal(policy.makerCheckerRequired, true);
    assert.equal(
      policy.predecessorPolicyId,
      index <= 1 ? null : normalized[index - 2].retentionPolicyId,
    );
    assert.match(policy.activationReceiptDigest, digestPattern);
  }
  assert.equal(new Set(policies.map((p) => p.retentionPolicyId)).size, 5);
  return search[0];
}

export function authenticationResumeState(state) {
  assert.deepEqual(state, { jobs: 0, retirements: 0, audit_policies: 0, pending: 0 });
}

export async function retainedAuthenticationFiles(
  input,
  root,
  dataRoot,
  secretRoot,
  participantId,
  privacyDomainId,
) {
  assert.equal(dirname(input.workerRoot), resolve(root));
  assert.equal(await realpath(input.workerRoot), input.workerRoot);
  assert.equal(
    hash(await readFile(join(root, 'deployment-intent-actors.json'))),
    input.actorsDigest,
  );
  const bytes = await readFile(join(input.workerRoot, 'worker.json'));
  assert.equal(hash(bytes), input.workerDigest);
  const config = JSON.parse(bytes);
  assert.deepEqual(config.database, {
    host: '127.0.0.1',
    port: 55432,
    database: 'openpc_control',
    user: 'openpc_local_control_worker',
    passwordFile: join(secretRoot, 'control_worker_runtime_db_password.txt'),
  });
  assert.equal(config.scopes.length, 1);
  const scope = config.scopes[0];
  assert.equal(scope.participantId, participantId);
  assert.equal(scope.privacyDomainId, privacyDomainId);
  assert.equal(scope.source, 'AUTHENTICATION');
  assert.equal(scope.retentionSeconds, 60);
  assert.equal(scope.capacityBytes, 16 * 1024 * 1024);
  assert.equal(scope.activeKeyId, 'projection-source');
  assert.match(scope.streamId, /^projection-authentication-/u);
  assert.match(config.sinkId, /^projection-authentication-/u);
  assert.equal(scope.keys.length, 1);
  assert.equal(scope.keys[0].keyId, scope.activeKeyId);
  assert.deepEqual(
    scope.keys.map((key) => key.keyFile),
    Object.keys(input.keyDigests),
  );
  assert.equal(await realpath(config.vaultDirectory), config.vaultDirectory);
  assert.equal(
    dirname(config.vaultDirectory).startsWith(join(dataRoot, 'projection-authentication-')),
    true,
  );
  for (const key of scope.keys) {
    assert.equal(await realpath(key.keyFile), key.keyFile);
    assert.equal(dirname(key.keyFile), dirname(config.vaultDirectory));
    const material = await readFile(key.keyFile);
    assert.equal(material.length, 32);
    assert.equal(hash(material), input.keyDigests[key.keyFile]);
  }
  return config;
}
export function projectionDeletionPreflight(
  participant = '018f0000-0000-7000-8000-000000000101',
  privacy = '018f0000-0000-7000-8000-000000007201',
  foreign = foreignPrivacy(privacy),
  actorMode = 'bootstrap-evidence-projection-deletion',
) {
  const actors = JSON.parse(
    execFileSync(
      process.execPath,
      [
        '--import',
        'tsx',
        'tests/integration/local-runtime/deployment-intent-actors.mjs',
        'preflight-only',
        'preflight-only',
        participant,
        actorMode,
        privacy,
        foreign,
        '--preflight',
      ],
      { encoding: 'utf8', timeout: 15000 },
    ),
  );
  assert.equal(actors.participantId, participant);
  assert.ok(actors.privacyDomainIds.includes(privacy));
  assert.notEqual(actors.actors.maker.principalId, actors.actors.checker.principalId);
  for (const dataClass of ['SEARCH_PROJECTION', 'NORMALIZED_JSON_PROJECTION', 'AUDIT_EVIDENCE']) {
    const fields = Object.fromEntries(
      Object.entries(policyFields(dataClass)).map(([label, value]) => {
        const field = transactionForms['retention-policy'].fields.find(
          (item) => item.label === label,
        );
        assert.ok(field, label);
        return [field.name, value];
      }),
    );
    transactionCandidate(
      'retention-policy',
      transactionFields('retention-policy', fields),
      'Exact independent class policy.',
      participant,
    );
  }
  for (const kind of [
    'evidence-deletion-search',
    'evidence-deletion-normalized',
    'evidence-deletion-projection-continuation',
  ]) {
    const operation = transactionOperation(kind);
    assert.equal(operation.actionIntentId, 'ACT-EVIDENCE_DELETIONS_CREATE_PROJECTION_BATCH-V1');
    assert.equal(operation.createPath, '/api/v1/evidence-deletions/projection-batches');
    assert.equal(operation.binding.catalogOperationId, 'CFG-OP-DELETE-PROJECTION-BATCH');
  }
  for (const value of rpcRetirementPolicyCases) {
    const inputs = workbenchInputFields(
      transactionForms['retention-policy'].label,
      rpcRetirementPolicyFields('urn:openpc:resource:018f0000-0000-7000-8000-000000000401', value),
    );
    assert.equal(
      inputs.find((field) => field.name === 'predecessorPolicyId').label,
      'Previous retention policy reference (optional)',
    );
    const fields = Object.fromEntries(inputs.map(({ name, value: content }) => [name, content]));
    transactionCandidate(
      'retention-policy',
      transactionFields('retention-policy', fields),
      'Independent read-chain retention case.',
      participant,
    );
  }
  assert.equal(transactionForms['evidence-deletion'].label, 'Delete a local evidence payload');
  assert.equal(transactionForms['evidence-deletion'].fields[0].label, 'Evidence record reference');
  process.stdout.write(
    'OPENPC_PROJECTION_DELETION_PREFLIGHT|PASS|actual-policy|distinct-actors|exact-action-and-resource\n',
  );
}

/** Runs after real RPC admission/custody. It never fabricates a transition,
 * activation, source receipt, approval, checkpoint or retirement. */
export async function projectionDeletionBrowser({
  secretRoot,
  evidenceRoot,
  dataRoot,
  compose,
  participantId,
  privacyDomainId,
  rpcConfiguration,
  resumeRoot,
  authenticationResume,
  closedRpcOnly = false,
  rpcPayloadRecordIds,
  rpcDenialRecordId,
  rpcDenialResumeApprovalId,
  rpcTerminalResumeApprovals,
  rpcReadResumePolicyVersion,
  rpcPayloadResumeApprovalId,
  rpcSearchResumeApprovalIds,
  onApprovalRequested,
  desktopOnly = false,
  sourceReads = false,
  terminalCases = false,
  factConfiguration,
  factSourceProfile,
  factResumeApprovalId,
  factReadbackHoldId,
  deploymentConfiguration,
  businessConfiguration,
  deploymentReadback = false,
  deploymentResumeFinalized = false,
}) {
  assert.equal(typeof desktopOnly, 'boolean');
  assert.ok(
    !desktopOnly || rpcPayloadRecordIds,
    'Desktop-only mode requires the RPC payload journey',
  );
  if (onApprovalRequested !== undefined) {
    assert.equal(typeof onApprovalRequested, 'function');
    assert.ok(
      rpcPayloadRecordIds,
      'Approval observation belongs only to the original RPC payload/search continuation',
    );
  }
  if (authenticationResume !== undefined) {
    authenticationResumeInputs(authenticationResume);
    assert.equal(resumeRoot, authenticationResume.workerRoot);
    assert.ok(
      !closedRpcOnly &&
        !rpcPayloadRecordIds &&
        !rpcDenialRecordId &&
        !rpcDenialResumeApprovalId &&
        !rpcTerminalResumeApprovals &&
        !rpcReadResumePolicyVersion &&
        !rpcPayloadResumeApprovalId &&
        !rpcSearchResumeApprovalIds &&
        !sourceReads &&
        !terminalCases &&
        !factConfiguration &&
        !factSourceProfile &&
        !factResumeApprovalId &&
        !factReadbackHoldId &&
        !deploymentConfiguration &&
        !deploymentReadback &&
        !deploymentResumeFinalized &&
        !businessConfiguration,
    );
  }
  if (rpcReadResumePolicyVersion) {
    assert.equal(rpcReadResumePolicyVersion, '3.0.0');
    assert.equal(closedRpcOnly, true);
    assert.ok(
      !terminalCases &&
        !sourceReads &&
        !rpcTerminalResumeApprovals &&
        !rpcDenialRecordId &&
        !rpcPayloadRecordIds &&
        !resumeRoot &&
        !factConfiguration &&
        !deploymentConfiguration &&
        !businessConfiguration,
    );
  }
  if (rpcTerminalResumeApprovals) {
    rpcTerminalResumeInputs(rpcTerminalResumeApprovals);
    assert.equal(closedRpcOnly, true);
    assert.equal(terminalCases, true);
    assert.ok(
      !rpcDenialRecordId &&
        !rpcPayloadRecordIds &&
        !sourceReads &&
        !resumeRoot &&
        !factConfiguration &&
        !deploymentConfiguration &&
        !businessConfiguration,
    );
  }
  if (rpcDenialRecordId !== undefined) {
    rpcDenialRetirementInput(rpcDenialRecordId);
    assert.ok(
      !rpcPayloadRecordIds &&
        !closedRpcOnly &&
        !sourceReads &&
        !terminalCases &&
        !factConfiguration &&
        !deploymentConfiguration &&
        !businessConfiguration &&
        !resumeRoot,
    );
  }
  if (rpcPayloadResumeApprovalId !== undefined) {
    assert.ok(rpcPayloadRecordIds);
    assert.match(rpcPayloadResumeApprovalId, /^[0-9a-f-]{36}$/u);
  }
  if (rpcPayloadRecordIds !== undefined) {
    rpcPayloadRetirementInputs(rpcPayloadRecordIds);
    assert.ok(
      !closedRpcOnly &&
        !sourceReads &&
        !terminalCases &&
        !factConfiguration &&
        !deploymentConfiguration &&
        !businessConfiguration,
    );
  }
  const rpcPayloadReadbackOnly = rpcPayloadRetirementReadbackInputs(
    rpcPayloadRecordIds,
    rpcPayloadResumeApprovalId,
    rpcSearchResumeApprovalIds,
  );
  const root = join(
    evidenceRoot,
    businessConfiguration ? 'retention-search-browser' : 'projection-deletion-browser',
  );
  if (rpcPayloadReadbackOnly)
    await access(join(root, 'deployment-intent-actors.json')).catch((error) => {
      if (error.code === 'ENOENT')
        throw new Error('Original RPC retirement actor file is required for readback', {
          cause: error,
        });
      throw error;
    });
  const retainedAuthentication = authenticationResume
    ? await retainedAuthenticationFiles(
        authenticationResume,
        root,
        dataRoot,
        secretRoot,
        participantId,
        privacyDomainId,
      )
    : undefined;
  await exec('bash', [
    'scripts/maintenance/run-bounded.sh',
    '--profile',
    'runtime-target',
    '--reuse',
    '--',
    'true',
  ]);
  assert.deepEqual(compose.slice(0, 2), ['docker', 'compose']);
  const command = (args) =>
    exec(compose[0], [...compose.slice(1), ...args], { timeout: 90000, maxBuffer: 1048576 });
  const actorMode = businessConfiguration
    ? 'bootstrap-evidence-retention-search'
    : 'bootstrap-evidence-projection-deletion';
  const artifacts = join(root, new Date().toISOString().replaceAll(':', '-'));
  await mkdir(artifacts, { recursive: true, mode: 0o700 });
  const pool = new Pool({
    host: '127.0.0.1',
    port: 55432,
    database: 'openpc_control',
    user: 'openpc_control',
    password: (await readFile(join(secretRoot, 'control_pg_password.txt'), 'utf8')).trim(),
    max: 1,
  });
  const foreign =
    factConfiguration || deploymentConfiguration || businessConfiguration
      ? (
          await pool.query(
            "select privacy_domain_id::text id from control.privacy_domain where participant_id=$1 and privacy_domain_id<>$2 and state='ACTIVE' order by privacy_domain_id limit 1",
            [participantId, privacyDomainId],
          )
        ).rows[0]?.id
      : foreignPrivacy(privacyDomainId);
  assert.ok(foreign, 'The source browser requires an existing foreign context');
  projectionDeletionPreflight(participantId, privacyDomainId, foreign, actorMode);
  if (
    !(await access(join(root, 'deployment-intent-actors.json')).then(
      () => true,
      (error) => {
        if (error.code !== 'ENOENT') throw error;
        return false;
      },
    ))
  ) {
    assert.equal(rpcPayloadReadbackOnly, false, 'Original RPC readback must not bootstrap actors');
    await exec(
      process.execPath,
      [
        '--import',
        'tsx',
        'tests/integration/local-runtime/deployment-intent-actors.mjs',
        secretRoot,
        root,
        participantId,
        actorMode,
        privacyDomainId,
        foreign,
      ],
      { timeout: 30000, maxBuffer: 65536 },
    );
  }
  if (businessConfiguration)
    assert.ok(
      !deploymentConfiguration && !factConfiguration && !rpcConfiguration,
      'Retention search requires its isolated original source configuration',
    );
  const scoped = [participantId, privacyDomainId];
  const sourceConfiguration =
    businessConfiguration ?? deploymentConfiguration ?? factConfiguration ?? rpcConfiguration;
  const rpcConfig = JSON.parse(await readFile(sourceConfiguration, 'utf8'));
  const selectedScope = factConfiguration
    ? rpcConfig.scopes.find((s) => s.fact?.sourceProfileId === factSourceProfile)
    : rpcConfig.scopes[0];
  assert.ok(selectedScope);
  assert.equal(selectedScope.participantId, participantId);
  assert.equal(selectedScope.privacyDomainId, privacyDomainId);
  assert.equal(
    selectedScope.source,
    businessConfiguration
      ? 'BUSINESS_TRANSITION'
      : deploymentConfiguration
        ? 'EFFECT'
        : factConfiguration
          ? 'FACT'
          : 'RPC',
  );
  if (factConfiguration || deploymentConfiguration || businessConfiguration)
    assert.equal(closedRpcOnly || sourceReads || terminalCases, false);
  else assert.equal(rpcConfig.scopes.length, 1);
  const rpcStream = selectedScope.streamId;
  const preservedStreams = businessConfiguration
    ? []
    : factConfiguration
      ? rpcConfig.scopes.map((s) => s.streamId)
      : [rpcStream];
  const container = (await command(['ps', '-q', 'control-api'])).stdout.trim();
  const image = JSON.parse(
    (await exec('docker', ['image', 'inspect', 'openpc-r1-dev/control-api:local'])).stdout,
  )[0];
  assert.equal(
    JSON.parse((await exec('docker', ['inspect', container])).stdout)[0].Image,
    image.Id,
  );
  const executable = join(artifacts, 'evidence-worker.mjs');
  await exec('docker', ['cp', `${container}:/app/evidence-worker.mjs`, executable]);
  if (deploymentConfiguration)
    await exec('docker', [
      'cp',
      `${container}:/app/result-source.sql`,
      join(artifacts, 'result-source.sql'),
    ]);
  const rpcReader = join(artifacts, 'runtime_evidence_reader');
  await exec('docker', ['cp', `${container}:/usr/local/bin/runtime_evidence_reader`, rpcReader]);
  await chmod(rpcReader, 0o700);
  const factReader = join(artifacts, 'policy_fact_reader');
  if (factConfiguration) {
    await exec('docker', ['cp', `${container}:/usr/local/bin/policy_fact_reader`, factReader]);
    await chmod(factReader, 0o700);
  }
  const runWorker = (configuration) =>
    exec(process.execPath, [executable, '--once'], {
      env: {
        ...process.env,
        OPENPC_RUNTIME_EVIDENCE_READER_BIN: rpcReader,
        ...(factConfiguration ? { OPENPC_POLICY_FACT_READER_BIN: factReader } : {}),
        OPENPC_EVIDENCE_WORKER_CONFIG_FILE: configuration,
      },
      timeout: 30000,
      maxBuffer: 65536,
    });
  let authConfig;
  if (
    rpcPayloadRecordIds ||
    rpcDenialRecordId ||
    closedRpcOnly ||
    factConfiguration ||
    deploymentConfiguration ||
    businessConfiguration
  ) {
    assert.equal(resumeRoot, undefined);
  } else if (resumeRoot) {
    assert.equal(
      dirname(resolve(resumeRoot)),
      resolve(root),
      'Resume must belong to this exact journey',
    );
    authConfig =
      retainedAuthentication ?? JSON.parse(await readFile(join(resumeRoot, 'worker.json'), 'utf8'));
    assert.equal(authConfig.scopes.length, 1);
    assert.equal(authConfig.scopes[0].participantId, participantId);
    assert.equal(authConfig.scopes[0].privacyDomainId, privacyDomainId);
    assert.equal(authConfig.scopes[0].source, 'AUTHENTICATION');
    assert.equal(authConfig.scopes[0].retentionSeconds, 60);
    assert.ok(authConfig.vaultDirectory.startsWith(join(dataRoot, 'projection-authentication-')));
  } else {
    const sourceRoot = join(dataRoot, `projection-authentication-${uuidv7()}`);
    await mkdir(sourceRoot, { mode: 0o700 });
    await writeFile(join(sourceRoot, 'key'), randomBytes(32), { mode: 0o600, flag: 'wx' });
    authConfig = {
      database: {
        host: '127.0.0.1',
        port: 55432,
        database: 'openpc_control',
        user: 'openpc_local_control_worker',
        passwordFile: join(secretRoot, 'control_worker_runtime_db_password.txt'),
      },
      vaultDirectory: join(sourceRoot, 'vault'),
      sinkId: `projection-authentication-${uuidv7()}`,
      scopes: [
        {
          participantId,
          privacyDomainId,
          streamId: `projection-authentication-${uuidv7()}`,
          source: 'AUTHENTICATION',
          activeKeyId: 'projection-source',
          keys: [{ keyId: 'projection-source', keyFile: join(sourceRoot, 'key') }],
          retentionSeconds: 60,
          capacityBytes: 16 * 1024 * 1024,
        },
      ],
    };
  }
  const authStream = authConfig?.scopes[0].streamId;
  const authConfiguration = join(artifacts, 'worker.json');
  if (authConfig) await writeFile(authConfiguration, JSON.stringify(authConfig), { mode: 0o600 });
  let preserveAuthenticationArchive;
  try {
    if (authenticationResume) {
      const trust = (
        await pool.query(
          `select to_jsonb(s) selection,to_jsonb(k) key,to_jsonb(st) key_state,to_jsonb(p) profile
        from control.business_signing_selection s join control.business_signing_key k using(participant_id,privacy_domain_id,signer_id)
        join control.business_signing_key_state st using(participant_id,privacy_domain_id,signer_id)
        join control.business_transition_profile p using(profile_digest)
        where s.participant_id=$1 and s.privacy_domain_id=$2 order by s.environment_id,s.profile_digest`,
          scoped,
        )
      ).rows;
      assert.deepEqual(trust, authenticationResume.trust);
      const vault = await LocalEvidenceVault.open(authConfig.vaultDirectory, authConfig.sinkId);
      for (const { checkpoint } of authenticationResume.checkpoints) {
        assert.equal(checkpoint.participant_id, participantId);
        assert.equal(checkpoint.privacy_domain_id, privacyDomainId);
        assert.equal(checkpoint.stream_id, authStream);
        assert.equal(checkpoint.sink_id, authConfig.sinkId);
      }
      const objects = authenticationResume.checkpoints.map(
        ({ checkpoint }) => checkpoint.receipt.object,
      );
      const bytes = await Promise.all(objects.map((object) => vault.read(object)));
      const through = authenticationResume.checkpoints
        .map(({ checkpoint }) => BigInt(checkpoint.receipt.object.throughSequence))
        .reduce((left, right) => (left > right ? left : right))
        .toString();
      preserveAuthenticationArchive = async () => {
        const original = (
          await pool.query(
            'select to_jsonb(c) checkpoint from control.evidence_checkpoint c where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 and sink_id=$4 and through_sequence<=$5 order by sink_id,through_sequence',
            [...scoped, authStream, authConfig.sinkId, through],
          )
        ).rows;
        assert.deepEqual(original, authenticationResume.checkpoints);
        for (const [index, object] of objects.entries())
          assert.deepEqual(await vault.read(object), bytes[index]);
      };
      await preserveAuthenticationArchive();
    } else if (!rpcPayloadReadbackOnly)
      await exec(
        process.execPath,
        [
          '--import',
          'tsx',
          'tests/integration/local-runtime/business-signing-bootstrap.mjs',
          secretRoot,
          participantId,
          privacyDomainId,
          rpcPayloadRecordIds ? '--rpc-retirement-trust' : '--projection-deletion-trust',
        ],
        { timeout: 30000, maxBuffer: 65536 },
      );
    const rpc =
      authenticationResume ||
      rpcPayloadRecordIds ||
      rpcDenialRecordId ||
      factConfiguration ||
      deploymentConfiguration ||
      businessConfiguration
        ? []
        : (
            await pool.query(
              `select c.evidence_id::text id,c.record_id,c.receipt_digest,c.sequence::text sequence,p.projection
      from control.evidence_catalogue c join control.evidence_rpc_provenance p using(participant_id,privacy_domain_id,stream_id,record_id)
      where c.participant_id=$1 and c.privacy_domain_id=$2 and c.stream_id=$3 and p.projection->'transition'->>'phase'='PRE_ADMISSION_DENIAL'
      order by c.record_id desc limit 2`,
              [...scoped, rpcStream],
            )
          ).rows.reverse();
    if (
      !authenticationResume &&
      !rpcPayloadRecordIds &&
      !rpcDenialRecordId &&
      !factConfiguration &&
      !deploymentConfiguration &&
      !businessConfiguration
    )
      assert.equal(rpc.length, 2, 'Two real pre-admission denials are required');
    const preserved = async () => ({
      unrelated: authenticationResume
        ? (
            await pool.query(
              `select
        (select jsonb_agg(to_jsonb(c) order by stream_id,sequence) from control.evidence_catalogue c where participant_id=$1 and privacy_domain_id=$2 and stream_id<>$3) catalogue,
        (select jsonb_agg(to_jsonb(p) order by stream_id,segment_id) from control.evidence_segment_payload p where participant_id=$1 and privacy_domain_id=$2 and stream_id<>$3) payloads,
        (select jsonb_agg(to_jsonb(c) order by stream_id,sink_id,through_sequence) from control.evidence_checkpoint c where participant_id=$1 and privacy_domain_id=$2 and stream_id<>$3) checkpoints`,
              [...scoped, authStream],
            )
          ).rows
        : undefined,
      catalogue: (
        await pool.query(
          'select * from control.evidence_catalogue where participant_id=$1 and privacy_domain_id=$2 and stream_id=any($3::text[]) order by stream_id,sequence',
          [...scoped, preservedStreams],
        )
      ).rows,
      payloads: (
        await pool.query(
          'select * from control.evidence_segment_payload where participant_id=$1 and privacy_domain_id=$2 and stream_id=any($3::text[]) order by stream_id,segment_id',
          [...scoped, preservedStreams],
        )
      ).rows,
      checkpoints: (
        await pool.query(
          'select * from control.evidence_checkpoint where participant_id=$1 and privacy_domain_id=$2 and stream_id=any($3::text[]) order by stream_id,sink_id,through_sequence',
          [...scoped, preservedStreams],
        )
      ).rows,
    });
    const before = await preserved();
    const rpcVault = await LocalEvidenceVault.open(rpcConfig.vaultDirectory, rpcConfig.sinkId);
    const rpcBytes = await Promise.all(
      before.checkpoints.map((row) => rpcVault.read(row.receipt.object)),
    );
    let retiredRpcRecordIds;
    await withTransactionBrowser(
      {
        secretRoot,
        evidenceRoot: root,
        artifacts,
        route: '/operate/evidence',
        privacyDomainId,
        reuseSessions: true,
        preserveActorFile: Boolean(authenticationResume || rpcPayloadRecordIds),
      },
      async ({ maker, checker, actors }) => {
        const govern = (label, fields, reason, loseExecutionResponse = false, beforeExecute) => {
          assert.equal(
            rpcPayloadReadbackOnly,
            false,
            'Original readback must not submit a business command',
          );
          return governThroughWorkbench({
            maker,
            checker,
            checkerId: actors.checker.principalId,
            label,
            fields,
            reason,
            loseExecutionResponse,
            beforeExecute,
            onApprovalRequested: async (approvalId) =>
              onApprovalRequested?.({ label, fields, reason, approvalId }),
          });
        };
        const api = await publicEvidenceReader(maker, secretRoot, participantId, privacyDomainId);
        const refresh = async () => {
          const pending = maker.waitForResponse(
            (r) =>
              new URL(r.url()).pathname === endpoint &&
              !new URL(r.url()).search &&
              r.request().method() === 'GET',
          );
          await maker.getByRole('button', { name: 'Refresh evidence', exact: true }).click();
          const response = await pending;
          assert.equal(response.status(), 200);
          return response.json();
        };
        const inspect = async (button) => {
          const pending = maker.waitForResponse(
            (r) =>
              new URL(r.url()).pathname === endpoint &&
              !!new URL(r.url()).search &&
              r.request().method() === 'GET',
          );
          await button.click();
          const response = await pending;
          assert.equal(response.status(), 200);
          return (await response.json()).plan;
        };
        const recordItem = async (row) => {
          await refresh();
          await maker
            .getByLabel('Find records by receipt digest', { exact: true })
            .fill(row.receipt_digest);
          const pending = maker.waitForResponse(
            (r) =>
              new URL(r.url()).pathname === endpoint &&
              new URL(r.url()).searchParams.has('recordDigest'),
          );
          await maker.getByLabel('Find records by receipt digest', { exact: true }).press('Enter');
          assert.equal((await pending).status(), 200);
          const item = maker
            .getByRole('region', { name: 'Evidence catalogue', exact: true })
            .getByRole('listitem')
            .filter({ hasText: urn(row.id) });
          await expect(item).toHaveCount(1);
          await openEvidenceRecordActions(item);
          return item;
        };
        const verify = async (result) => {
          const receipt = (
            await pool.query(
              `select a.receipt_cbor,a.cose_sign1,k.public_key_spki_der from control.audit_occurrence a join control.business_signing_key k using(participant_id,privacy_domain_id,signer_id) where a.participant_id=$1 and a.privacy_domain_id=$2 and a.operation_id=$3 and a.aggregate_type='evidence-deletion'`,
              [...scoped, result.operationId],
            )
          ).rows;
          assert.equal(receipt.length, 1);
          assert.ok(
            verifyReceiptCose(
              receipt[0].public_key_spki_der,
              receipt[0].receipt_cbor,
              receipt[0].cose_sign1,
            ),
          );
          assert.equal(
            decodeAdmittedReceipt(receipt[0].receipt_cbor).transitionProfileId,
            'pc.control.evidence-deletion.projection',
          );
          const retired = (
            await pool.query(
              'select projection_bytes from control.evidence_projection_retirement where participant_id=$1 and privacy_domain_id=$2 and deletion_job_id=$3',
              [...scoped, result.deletionJobId.slice(-36)],
            )
          ).rows;
          assert.equal(retired.length, 1);
          assert.equal(result.deletedBytes, String(retired[0].projection_bytes));
        };
        const continueFrom = async (result) => {
          await refresh();
          await expect(maker.getByText('Scoped evidence loaded.', { exact: true })).toBeVisible();
          const tasks = maker.getByRole('navigation', { name: 'Evidence tasks', exact: true });
          if (await tasks.count())
            await tasks.getByRole('button', { name: 'Data removal', exact: true }).click();
          const retention = maker
            .locator('details > summary')
            .filter({ hasText: /^Retention, preservation and deletion$/u });
          if (
            (await retention.count()) &&
            (await retention.locator('..').getAttribute('open')) === null
          ) {
            await retention.focus();
            await maker.keyboard.press('Enter');
          }
          const item = maker
            .getByRole('region', { name: 'Local deletion results', exact: true })
            .getByRole('listitem')
            .filter({ hasText: result.deletionJobId });
          await expect(item).toHaveCount(1);
          return projectionDeletionPlan.parse(
            await inspect(
              item.getByRole('button', { name: 'Read signed continuation', exact: true }),
            ),
          );
        };
        if (rpcDenialRecordId) {
          await rpcDenialRetirementBrowser({
            recordId: rpcDenialRecordId,
            resumeApprovalId: rpcDenialResumeApprovalId,
            maker,
            checker,
            api,
            govern,
            refresh,
            recordItem,
            inspect,
            verify,
            continueFrom,
            pool,
            scoped,
            rpcStream,
            command,
            runWorker: () => runWorker(rpcConfiguration),
            preserve: async () => {
              assert.deepEqual(await preserved(), before);
              for (const [index, row] of before.checkpoints.entries())
                assert.deepEqual(await rpcVault.read(row.receipt.object), rpcBytes[index]);
            },
          });
          return;
        }
        if (rpcPayloadRecordIds) {
          await rpcPayloadSearchRetirementBrowser({
            recordIds: rpcPayloadRecordIds,
            desktopOnly,
            resumePayloadApprovalId: rpcPayloadResumeApprovalId,
            resumeSearchApprovalIds: rpcSearchResumeApprovalIds,
            maker,
            api,
            govern,
            refresh,
            recordItem,
            inspect,
            verify,
            continueFrom,
            pool,
            scoped,
            streamId: rpcStream,
            configuration: rpcConfig,
            runWorker: () => runWorker(sourceConfiguration),
            command,
            artifacts,
            foreignPrivacyDomainId: foreign,
          });
          return;
        }
        if (businessConfiguration) {
          await retentionSearchProjectionBrowser({
            maker,
            api,
            govern,
            refresh,
            recordItem,
            inspect,
            verify,
            continueFrom,
            pool,
            scoped,
            streamId: rpcStream,
            configuration: rpcConfig,
            runWorker: () => runWorker(sourceConfiguration),
            command,
            artifacts,
            foreignPrivacyDomainId: foreign,
          });
          return;
        }
        if (factConfiguration || deploymentConfiguration) {
          await (
            deploymentConfiguration
              ? deploymentProjectionRetirementBrowser
              : factProjectionRetirementBrowser
          )({
            maker,
            checker,
            actors,
            api,
            govern,
            refresh,
            recordItem,
            inspect,
            verify,
            continueFrom,
            pool,
            scoped,
            streamId: rpcStream,
            secretRoot,
            artifacts,
            command,
            runWorker: () => runWorker(sourceConfiguration),
            configuration: rpcConfig,
            foreignPrivacyDomainId: foreign,
            resumeApprovalId: factResumeApprovalId,
            readbackHoldId: factReadbackHoldId,
            deploymentReadback,
            deploymentResumeFinalized,
            preserve: async () => {
              assert.deepEqual(await preserved(), before);
              for (const [index, row] of before.checkpoints.entries())
                assert.deepEqual(await rpcVault.read(row.receipt.object), rpcBytes[index]);
            },
          });
          return;
        }
        if (closedRpcOnly) {
          if (rpcTerminalResumeApprovals) {
            await rpcTerminalRemainderBrowser({
              approvals: rpcTerminalResumeApprovals,
              maker,
              api,
              govern,
              refresh,
              verify,
              continueFrom,
              pool,
              scoped,
              rpcStream,
              runWorker: () => runWorker(rpcConfiguration),
              command,
              artifacts,
              preserve: async () => {
                assert.deepEqual(await preserved(), before);
                for (const [index, row] of before.checkpoints.entries())
                  assert.deepEqual(await rpcVault.read(row.receipt.object), rpcBytes[index]);
              },
            });
            return;
          }
          retiredRpcRecordIds = await rpcProjectionRetirementBrowser({
            resumeActivePolicyVersion: rpcReadResumePolicyVersion,
            sourceReads,
            terminalCases,
            maker,
            checker,
            actors,
            api,
            govern,
            refresh,
            recordItem,
            inspect,
            verify,
            continueFrom,
            pool,
            scoped,
            rpcStream,
            secretRoot,
            artifacts,
            command,
            runWorker: () => runWorker(rpcConfiguration),
            preserve: async () => {
              assert.deepEqual(await preserved(), before);
              for (const [index, row] of before.checkpoints.entries())
                assert.deepEqual(await rpcVault.read(row.receipt.object), rpcBytes[index]);
            },
          });
          return;
        }
        for (const row of rpc) {
          const source = await api(`evidence-records/${urn(row.id)}/provenance`);
          assert.equal(source.status, 200);
          assert.equal(source.body.status, 'VERIFIED_RPC_CUSTODY_PROJECTION');
          assert.equal(source.body.rpc.transition.phase, 'PRE_ADMISSION_DENIAL');
        }
        // Resume only the measured pre-deletion checkpoint, with public durable
        // policy readback and the original archive configuration. Never replay it.
        if (resumeRoot) {
          const current = await refresh();
          assert.equal(current.retentionPoliciesUnavailable, false);
          assert.equal(current.retentionPolicies.nextCursor, null);
          const policies = current.retentionPolicies.items;
          if (authenticationResume) {
            authenticationResumePolicies(policies);
            const state = (
              await pool.query(
                `select
              (select count(*) from control.deletion_job where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3)::int jobs,
              (select count(*) from control.evidence_projection_retirement where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3)::int retirements,
              (select count(*) from control.retention_policy where participant_id=$1 and privacy_domain_id=$2 and data_class='AUDIT_EVIDENCE')::int audit_policies,
              (select count(*) from control.mutation_candidate where participant_id=$1 and privacy_domain_id=$2 and (catalog_operation_id like '%DELETE%' or catalog_operation_id like '%RETENTION%') and consumed_operation_id is null)::int pending`,
                [...scoped, authStream],
              )
            ).rows;
            assert.equal(state.length, 1);
            authenticationResumeState(state[0]);
            const checkpoints = (
              await pool.query(
                'select to_jsonb(c) checkpoint from control.evidence_checkpoint c where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 order by sink_id,through_sequence',
                [...scoped, authStream],
              )
            ).rows;
            assert.deepEqual(checkpoints, authenticationResume.checkpoints);
            const owners = (
              await pool.query(
                'select principal_id::text from control.mutation_evidence where participant_id=$1 and privacy_domain_id=$2 and operation_id=any($3::uuid[])',
                [...scoped, policies.map((p) => p.activationOperationId)],
              )
            ).rows;
            assert.equal(owners.length, 5);
            assert.ok(owners.every((p) => p.principal_id === actors.maker.principalId));
          }
          const matching = policies.filter((p) => p.dataClass === 'SEARCH_PROJECTION');
          assert.equal(matching.length, 1);
          assert.deepEqual(
            Object.fromEntries(
              [
                'state',
                'policyVersion',
                'retentionPeriodMs',
                'localGraceMs',
                'sinkQuorum',
                'deletionMode',
                'makerCheckerRequired',
              ].map((k) => [k, matching[0][k]]),
            ),
            {
              state: 'ACTIVE',
              policyVersion: '1.0.0',
              retentionPeriodMs: '0',
              localGraceMs: '0',
              sinkQuorum: 1,
              deletionMode: 'PROJECTION_DELETE',
              makerCheckerRequired: true,
            },
          );
          assert.match(matching[0].activationReceiptDigest, /^sha256:[0-9a-f]{64}$/u);
          if (!authenticationResume)
            assert.equal(
              policies.filter((p) =>
                ['NORMALIZED_JSON_PROJECTION', 'AUDIT_EVIDENCE'].includes(p.dataClass),
              ).length,
              0,
              'Later governance must be reconciled before another continuation',
            );
          const owner = await pool.query(
            'select principal_id::text from control.mutation_evidence where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3',
            [...scoped, matching[0].activationOperationId],
          );
          assert.equal(owner.rows[0]?.principal_id, actors.maker.principalId);
          assert.equal(
            (
              await pool.query(
                'select count(*)::int n from control.evidence_projection_retirement where participant_id=$1 and privacy_domain_id=$2 and stream_id=any($3::text[])',
                [...scoped, authenticationResume ? [authStream] : [authStream, rpcStream]],
              )
            ).rows[0].n,
            0,
          );
          process.stdout.write(
            authenticationResume
              ? 'OPENPC_AUTHENTICATION_RESUME|PASS|original-worker-key-actors-checkpoints-and-trust|exact-policy-chain|untouched-original-selection|no-rpc-replay\n'
              : 'OPENPC_PROJECTION_RESUME|PASS|public-original-policy|same-archive|no-deletion-replay\n',
          );
        } else {
          await govern(
            'Activate a retention policy version',
            policyFields('SEARCH_PROJECTION'),
            'Govern the independent search projection retention period.',
          );
        }
        const sourceCount = (
          await pool.query(
            'select count(*)::int n from control.authentication_occurrence where participant_id=$1 and privacy_domain_id=$2',
            scoped,
          )
        ).rows[0].n;
        let latest;
        for (let batch = 0; batch <= Math.ceil(sourceCount / 8); batch++) {
          if (!resumeRoot) await runWorker(authConfiguration);
          latest = (
            await pool.query(
              `select c.segment_id::text segment_id from control.evidence_catalogue c join control.authentication_occurrence a on a.occurrence_id::text=c.record_id where c.participant_id=$1 and c.privacy_domain_id=$2 and c.stream_id=$3 and a.method='WEBAUTHN_ASSERTION' and a.principal_id=$4 order by c.sequence desc limit 1`,
              [...scoped, authStream, actors.maker.principalId],
            )
          ).rows[0];
          if (latest) break;
          assert.equal(resumeRoot, undefined, 'Original retained authentication source must exist');
        }
        assert.ok(latest);
        // Choose the final two records in the current stream's immutable keyset.
        const auth = (
          await pool.query(
            'select evidence_id::text id,record_id,receipt_digest,segment_id::text segment_id,sequence::text sequence from control.evidence_catalogue where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 order by record_id desc limit 2',
            [...scoped, authStream],
          )
        ).rows.reverse();
        assert.equal(auth.length, 2);
        if (authenticationResume) assert.deepEqual(auth, authenticationResume.records);
        const originalAuthentication = authenticationResume
          ? (
              await pool.query(
                'select to_jsonb(a) occurrence from control.authentication_occurrence a where participant_id=$1 and privacy_domain_id=$2 and occurrence_id::text=any($3::text[]) order by occurrence_id',
                [...scoped, auth.map((row) => row.record_id)],
              )
            ).rows
          : undefined;
        for (const row of auth) {
          const blocked = await api(
            `evidence-records/${urn(row.id)}/search-projection-deletion-plan`,
          );
          assert.equal(blocked.status, 200);
          assert.ok(blocked.body.blockers.includes('REFERENCES'));
        }
        if (!authenticationResume) {
          await govern(
            'Activate a retention policy version',
            policyFields('NORMALIZED_JSON_PROJECTION'),
            'Govern independent normalized RPC projection retention.',
          );
          const unsupportedRpc = (
            await pool.query(
              `select c.evidence_id::text id from control.evidence_catalogue c
             join control.evidence_rpc_provenance p using(participant_id,privacy_domain_id,stream_id,record_id)
             where c.participant_id=$1 and c.privacy_domain_id=$2 and c.stream_id=$3
              and p.projection->'transition'->>'phase'<>'PRE_ADMISSION_DENIAL' limit 1`,
              [...scoped, rpcStream],
            )
          ).rows[0];
          assert.ok(
            unsupportedRpc,
            'The original real RPC journey must retain a post-admission source',
          );
          const completedRead = projectionDeletionPlan.parse(
            (
              await api(
                `evidence-records/${urn(unsupportedRpc.id)}/normalized-projection-deletion-plan`,
              )
            ).body,
          );
          assert.equal(completedRead.eligible, true);
          assert.equal(completedRead.selection.sourceKind, 'RPC_CLOSED_TRANSITION');
          const unsupported = projectionDeletionPlan.parse(
            (await api(`evidence-records/${urn(rpc[0].id)}/search-projection-deletion-plan`)).body,
          );
          assert.equal(unsupported.eligible, false);
          assert.equal(unsupported.selection, null);
          assert.ok(unsupported.blockers.includes('UNSUPPORTED_SOURCE'));
          const hold = await govern(
            'Preserve evidence under a hold',
            {
              'Hold kind': 'LEGAL',
              'Evidence to preserve': 'DIGEST',
              'Receipt digest': rpc[0].receipt_digest,
            },
            'Preserve the original denied RPC while its projection is selected.',
          );
          let item = await recordItem(rpc[0]);
          let plan = projectionDeletionPlan.parse(
            await inspect(
              item.getByRole('button', {
                name: `Review normalized projection deletion for sequence ${rpc[0].sequence}`,
                exact: true,
              }),
            ),
          );
          assert.ok(plan.blockers.includes('ACTIVE_HOLD'));
          await expect(
            maker.getByRole('button', { name: 'Prepare first deletion batch', exact: true }),
          ).toHaveCount(0);
          await govern(
            'Release an evidence hold',
            { 'Resource reference': hold.completed.result.holdId, 'Expected revision': '1' },
            'Release this exact source preservation hold.',
          );
          item = await recordItem(rpc[0]);
          plan = projectionDeletionPlan.parse(
            await inspect(
              item.getByRole('button', {
                name: `Review normalized projection deletion for sequence ${rpc[0].sequence}`,
                exact: true,
              }),
            ),
          );
          assert.equal(plan.eligible, true);
          assert.equal(plan.selection.targets.length, 2);
          await maker
            .getByRole('button', { name: 'Prepare first deletion batch', exact: true })
            .click();
          const first = await govern(
            'Delete normalized evidence projections',
            { 'Starting evidence reference': urn(rpc[0].id) },
            'Retire the exact normalized denial projection with preserved original evidence.',
            true,
          );
          await verify(first.completed.result);
          await command(['restart', 'control-api']);
          await command([
            'up',
            '-d',
            '--wait',
            '--no-deps',
            '--no-build',
            '--pull',
            'never',
            'control-api',
          ]);
          assert.deepEqual(
            (await readWorkbenchApproval(maker, first.approvalId)).result,
            first.completed.result,
          );
          assert.equal((await continueFrom(first.completed.result)).continuationState, 'READY');
          await maker
            .getByRole('button', { name: 'Prepare next deletion batch', exact: true })
            .click();
          const second = await govern(
            'Continue projection deletion',
            { 'Previous projection deletion result': first.completed.result.deletionJobId },
            'Continue the fixed normalized projection selection.',
          );
          await verify(second.completed.result);
          assert.equal((await continueFrom(second.completed.result)).continuationState, 'COMPLETE');
          await runWorker(rpcConfiguration);
          for (const row of rpc) {
            const source = await api(`evidence-records/${urn(row.id)}/provenance`);
            assert.equal(source.status, 200);
            assert.equal(source.body.status, 'PROJECTION_RETIRED');
            assert.equal(source.body.rpc, null);
            const retainedProof = await pool.query(
              `select openpc.rpc_retired_catalogue_proof(c) proof,openpc.rpc_retired_catalogue_has_references(c) referenced
             from control.evidence_catalogue c where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 and evidence_id=$4`,
              [...scoped, rpcStream, row.id],
            );
            assert.equal(retainedProof.rowCount, 1);
            assert.equal(retainedProof.rows[0].proof.sourceKind, 'RPC_PRE_ADMISSION_DENIAL');
            assert.equal(retainedProof.rows[0].proof.identityDigest, null);
            assert.equal(retainedProof.rows[0].proof.sourceReceiptDigest, row.receipt_digest);
            assert.equal(retainedProof.rows[0].referenced, false);
            const search = projectionDeletionPlan.parse(
              (await api(`evidence-records/${urn(row.id)}/search-projection-deletion-plan`)).body,
            );
            assert.equal(search.eligible, false);
            assert.ok(
              search.blockers.includes('REFERENCES'),
              'Original local ciphertext still protects catalogue',
            );
            assert.equal(search.blockers.includes('UNSUPPORTED_SOURCE'), false);
          }
          item = await recordItem(rpc[0]);
          await item
            .getByRole('button', {
              name: `Read provenance for sequence ${rpc[0].sequence}`,
              exact: true,
            })
            .click();
          await expect(
            maker.getByRole('region', { name: 'Evidence provenance', exact: true }),
          ).toContainText('This normalized projection was retired by an approved deletion.');
          await maker.screenshot({
            path: join(artifacts, 'normalized-projection-retired.png'),
            fullPage: true,
          });
          assert.deepEqual(await preserved(), before);
          for (const [index, row] of before.checkpoints.entries())
            assert.deepEqual(await rpcVault.read(row.receipt.object), rpcBytes[index]);
          const laterHold = await govern(
            'Preserve evidence under a hold',
            {
              'Hold kind': 'LEGAL',
              'Evidence to preserve': 'DIGEST',
              'Receipt digest': rpc[0].receipt_digest,
            },
            'Preserve the original RPC archive after its normalized projection retirement.',
          );
          await runWorker(rpcConfiguration);
          const coverage = await api(`evidence-holds/${laterHold.completed.result.holdId}`);
          assert.equal(coverage.status, 200);
          assert.equal(coverage.body.coverage, 'VERIFIED');
          await govern(
            'Release an evidence hold',
            { 'Resource reference': laterHold.completed.result.holdId, 'Expected revision': '1' },
            'Release the exact archive hold after verifying retirement-safe preservation.',
          );
          await runWorker(rpcConfiguration);
          process.stdout.write(
            'OPENPC_PROJECTION_DELETION_BROWSER|normalized-passed|real-rpc|two-physical-effects|preserved-custody|restart-no-rebuild\n',
          );
        }
        // The worker's original sixty-second storage promises remain in force.
        await govern(
          'Activate a retention policy version',
          policyFields('AUDIT_EVIDENCE'),
          'Clear local ciphertext references through their separate governed owner.',
        );
        const payloadResults = [];
        for (const segmentId of new Set(auth.map((row) => row.segment_id))) {
          const row = auth.find((candidate) => candidate.segment_id === segmentId);
          await expect
            .poll(
              async () => {
                const current = await api(`evidence-records/${urn(row.id)}/deletion-plan`);
                assert.equal(current.status, 200);
                assert.ok(
                  current.body.blockers.every((blocker) => blocker === 'RETENTION_NOT_ELAPSED'),
                );
                return current.body.eligible;
              },
              { timeout: 65000, intervals: [1000] },
            )
            .toBe(true);
          const payloadPlan = localEvidenceDeletionPlan.parse(
            (await api(`evidence-records/${urn(row.id)}/deletion-plan`)).body,
          );
          assert.equal(payloadPlan.eligible, true);
          assert.equal(payloadPlan.selection.segmentId, segmentId);
          const local = await govern(
            'Delete a local evidence payload',
            { 'Evidence record reference': urn(row.id) },
            'Clear this independently retained local ciphertext reference.',
            !!authenticationResume && payloadResults.length === 0,
          );
          const receipts = (
            await pool.query(
              `select a.receipt_cbor,a.cose_sign1,k.public_key_spki_der from control.audit_occurrence a
            join control.business_signing_key k using(participant_id,privacy_domain_id,signer_id)
            where a.participant_id=$1 and a.privacy_domain_id=$2 and a.operation_id=$3`,
              [...scoped, local.completed.result.operationId],
            )
          ).rows;
          assert.equal(receipts.length, 1);
          assert.equal(
            verifyReceiptCose(
              receipts[0].public_key_spki_der,
              receipts[0].receipt_cbor,
              receipts[0].cose_sign1,
            ),
            true,
          );
          const receipt = decodeAdmittedReceipt(receipts[0].receipt_cbor);
          assert.equal(receipt.transitionProfileId, 'pc.control.evidence-deletion.local');
          assert.equal(receipt.transitionProfileVersion, 1);
          assert.equal(
            local.completed.result.deletedBytes,
            String(payloadPlan.selection.ciphertextBytes),
          );
          assert.equal(
            (
              await pool.query(
                'select count(*)::int n from control.evidence_segment_payload where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 and segment_id=$4',
                [...scoped, authStream, segmentId],
              )
            ).rows[0].n,
            0,
          );
          payloadResults.push(local);
        }
        const item = await recordItem(auth[0]);
        const plan = projectionDeletionPlan.parse(
          await inspect(
            item.getByRole('button', {
              name: `Review search projection deletion for sequence ${auth[0].sequence}`,
              exact: true,
            }),
          ),
        );
        assert.equal(plan.eligible, true);
        assert.equal(plan.selection.targets.length, 2);
        await maker
          .getByRole('button', { name: 'Prepare first deletion batch', exact: true })
          .click();
        const searchFirst = await govern(
          'Delete search projections',
          { 'Starting catalogue evidence reference': urn(auth[0].id) },
          'Retire an unreferenced authentication catalogue projection.',
        );
        await verify(searchFirst.completed.result);
        assert.equal((await continueFrom(searchFirst.completed.result)).continuationState, 'READY');
        const searchSecond = await govern(
          'Continue projection deletion',
          { 'Previous projection deletion result': searchFirst.completed.result.deletionJobId },
          'Retire the next exact authentication catalogue projection.',
        );
        await verify(searchSecond.completed.result);
        assert.equal(
          (await continueFrom(searchSecond.completed.result)).continuationState,
          'COMPLETE',
        );
        if (authenticationResume) {
          const results = [...payloadResults, searchFirst, searchSecond];
          const durable = async () =>
            (
              await pool.query(
                `select to_jsonb(j) job,to_jsonb(a) receipt from control.deletion_job j
            join control.audit_occurrence a using(participant_id,privacy_domain_id,operation_id)
            where j.participant_id=$1 and j.privacy_domain_id=$2 and j.operation_id=any($3::uuid[]) order by j.deletion_job_id`,
                [...scoped, results.map((r) => r.completed.result.operationId)],
              )
            ).rows;
          const effects = await durable();
          assert.equal(effects.length, results.length);
          assert.ok(effects.every((r) => r.job.state === 'SUCCEEDED' && r.job.revision === 1));
          await command(['restart', 'control-api']);
          await command([
            'up',
            '-d',
            '--wait',
            '--no-deps',
            '--no-build',
            '--pull',
            'never',
            'control-api',
          ]);
          for (const result of results)
            assert.deepEqual(
              (await readWorkbenchApproval(maker, result.approvalId)).result,
              result.completed.result,
            );
          assert.deepEqual(await durable(), effects);
          await preserveAuthenticationArchive();
        }
        await runWorker(authConfiguration);
        if (authenticationResume) {
          await preserveAuthenticationArchive();
          assert.equal(
            (
              await pool.query(
                'select count(*)::int n from control.evidence_segment_payload where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 and segment_id=any($4::uuid[])',
                [...scoped, authStream, auth.map((r) => r.segment_id)],
              )
            ).rows[0].n,
            0,
          );
          assert.deepEqual(
            (
              await pool.query(
                'select to_jsonb(a) occurrence from control.authentication_occurrence a where participant_id=$1 and privacy_domain_id=$2 and occurrence_id::text=any($3::text[]) order by occurrence_id',
                [...scoped, auth.map((row) => row.record_id)],
              )
            ).rows,
            originalAuthentication,
          );
          assert.deepEqual(await preserved(), before);
          for (const [index, row] of before.checkpoints.entries())
            assert.deepEqual(await rpcVault.read(row.receipt.object), rpcBytes[index]);
          assert.equal(
            (await continueFrom(searchSecond.completed.result)).continuationState,
            'COMPLETE',
          );
        }
        assert.equal(
          (
            await pool.query(
              'select count(*)::int n from control.evidence_catalogue where participant_id=$1 and privacy_domain_id=$2 and evidence_id=any($3::uuid[])',
              [...scoped, auth.map((row) => row.id)],
            )
          ).rows[0].n,
          0,
        );
        assert.equal(
          (
            await pool.query(
              'select count(*)::int n from control.authentication_occurrence where participant_id=$1 and privacy_domain_id=$2 and occurrence_id::text=any($3::text[])',
              [...scoped, auth.map((row) => row.record_id)],
            )
          ).rows[0].n,
          2,
        );
        for (const override of [
          { participantId: uuidv7() },
          { privacyDomainId: '018f0000-0000-7000-8000-000000000201' },
        ]) {
          const denied = await api(
            `evidence-deletions/${searchSecond.completed.result.deletionJobId}/projection-continuation-plan`,
            override,
          );
          assert.ok([403, 404].includes(denied.status));
          const deniedBody = JSON.stringify(denied.body);
          for (const value of [
            searchSecond.completed.result.receiptDigest,
            searchSecond.completed.result.deletionJobId,
            searchSecond.completed.result.operationId,
            ...auth.flatMap((r) => [r.id, r.record_id, r.receipt_digest]),
            'selection',
            'targets',
            'priorCursor',
            'continuationState',
          ])
            assert.equal(deniedBody.includes(value), false);
        }
        await maker
          .getByRole('button', { name: 'Refresh deletion eligibility', exact: true })
          .focus();
        await maker.keyboard.press('Enter');
        await expect(
          maker.getByRole('region', { name: 'Local deletion eligibility', exact: true }),
        ).toContainText('Selection complete.');
        assert.deepEqual((await new AxeBuilder({ page: maker }).analyze()).violations, []);
        await maker.screenshot({
          path: join(artifacts, 'projection-deletion-desktop.png'),
          fullPage: true,
        });
        await maker.setViewportSize({ width: 360, height: 880 });
        assert.equal(
          await maker.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
          true,
        );
        assert.deepEqual((await new AxeBuilder({ page: maker }).analyze()).violations, []);
        await maker.screenshot({
          path: join(artifacts, 'projection-deletion-reflow.png'),
          fullPage: true,
        });
        process.stdout.write(
          authenticationResume
            ? `OPENPC_AUTHENTICATION_RETIREMENT_BROWSER|PASS|original-two-records|payload-effects=${payloadResults.length}|search-effects=2|references-denial|signed-receipts-and-cursors|lost-response|restart|no-resurrection|original-occurrences-and-unrelated-custody|privacy|keyboard|axe|reflow\n`
            : 'OPENPC_PROJECTION_DELETION_BROWSER|PASS|actual-rpc-authentication|independent-policies|holds|reference-clearance|four-physical-effects|signed-cursors|lost-response|restart|packaged-recovery|privacy|keyboard|axe|reflow\n',
        );
      },
    );
    return retiredRpcRecordIds;
  } finally {
    await pool.end();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  if (process.argv[2] === '--preflight') {
    projectionDeletionPreflight(process.argv[3], process.argv[4], process.argv[5], process.argv[6]);
    if (process.env.OPENPC_RPC_DENIAL_RETIREMENT_RECORD_ID !== undefined)
      rpcDenialRetirementInput(process.env.OPENPC_RPC_DENIAL_RETIREMENT_RECORD_ID);
    if (process.env.OPENPC_RPC_PAYLOAD_RETIREMENT_RECORD_IDS !== undefined)
      rpcPayloadRetirementInputs(JSON.parse(process.env.OPENPC_RPC_PAYLOAD_RETIREMENT_RECORD_IDS));
  } else if (process.argv[2] === '--retention-search') {
    assert.equal(process.argv.length, 5);
    await exec('bash', [
      'scripts/maintenance/run-bounded.sh',
      '--profile',
      'runtime-target',
      '--reuse',
      '--',
      'true',
    ]);
    const [ownerRoot, composeJson] = process.argv.slice(3);
    const { prepareRetentionSearchBrowser } =
      await import('./evidence-retention-search-browser.mjs');
    await projectionDeletionBrowser({
      ...(await prepareRetentionSearchBrowser(ownerRoot)),
      compose: JSON.parse(composeJson),
    });
  } else {
    const [
      secretRoot,
      evidenceRoot,
      dataRoot,
      composeJson,
      participantId,
      privacyDomainId,
      rpcConfiguration,
    ] = process.argv.slice(2);
    await projectionDeletionBrowser({
      secretRoot,
      evidenceRoot,
      dataRoot,
      compose: JSON.parse(composeJson),
      participantId,
      privacyDomainId,
      rpcConfiguration,
      businessConfiguration: process.env.OPENPC_PROJECTION_DELETION_BUSINESS_CONFIG,
      resumeRoot: process.env.OPENPC_PROJECTION_DELETION_RESUME_ROOT,
      closedRpcOnly: process.env.OPENPC_PROJECTION_DELETION_RPC_CLOSED_ONLY === '1',
      rpcDenialRecordId: process.env.OPENPC_RPC_DENIAL_RETIREMENT_RECORD_ID,
      rpcDenialResumeApprovalId: process.env.OPENPC_RPC_DENIAL_RESUME_APPROVAL_ID,
      rpcPayloadResumeApprovalId: process.env.OPENPC_RPC_PAYLOAD_RESUME_APPROVAL_ID,
      rpcSearchResumeApprovalIds:
        process.env.OPENPC_RPC_SEARCH_RESUME_APPROVAL_IDS === undefined
          ? undefined
          : JSON.parse(process.env.OPENPC_RPC_SEARCH_RESUME_APPROVAL_IDS),
      rpcPayloadRecordIds:
        process.env.OPENPC_RPC_PAYLOAD_RETIREMENT_RECORD_IDS === undefined
          ? undefined
          : JSON.parse(process.env.OPENPC_RPC_PAYLOAD_RETIREMENT_RECORD_IDS),
      sourceReads: process.env.OPENPC_RPC_RETIREMENT_SOURCE_READS === '1',
      terminalCases: process.env.OPENPC_RPC_RETIREMENT_TERMINAL_CASES === '1',
    });
  }
}
