import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';
import { publicReadResponse } from './authenticated-http.mjs';
import { execFile } from 'node:child_process';
import { createHash, createPublicKey } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { Pool } from 'pg';
import { uuidv7 } from '../../../services/control-api/src/configuration/governed-mutation-http.ts';
import {
  parseRetirementWire,
  retirementAttempt,
  verifyRetirementOutcome,
  retirementSelection,
  retirementWireBytes,
  retirementWireDigest,
} from '../../../services/control-api/src/evidence/store-retirement-wire.ts';
import {
  transactionCandidate,
  transactionOperation,
} from '../../../apps/admin-web/app/api/v1/ui/transaction-workbench-contract.ts';
import { transactionFields } from '../../../apps/admin-web/lib/transaction-workflow.ts';
import { projectApprovalCandidate } from '../../../services/module-registry/src/approval-candidate-contract.ts';
import { parseFactRetirementTarget } from '../../../services/control-api/src/evidence/store-retirement-dispatcher.ts';
import { readFactRetirementSelection } from '../../../services/control-api/src/evidence/store-retirement-selection.ts';
import {
  admitStoreRetirement,
  storeRetirementPlan,
  storeRetirementPlanInput,
} from '../../../services/control-api/src/evidence/store-retirement-contracts.ts';

// Select the actual publicly admitted and withdrawn Fact. These database reads
// supply exact inputs, never lifecycle state or permission to retire anything.
const [mode, root] = process.argv.slice(2);
assert.ok(
  [
    'preflight',
    'prepare',
    'plan',
    'candidate',
    'verify',
    'verify-restart',
    'recovery',
    'selection',
    'api-selection',
  ].includes(mode),
);
const evidence = join(root, 'evidence/runtime-bootstrap');
const directory = join(evidence, 'store-retirement');
await mkdir(directory, { recursive: true, mode: 0o700 });
const json = async (path) => JSON.parse(await readFile(path, 'utf8'));
const load = (name) => json(join(directory, name));
const save = async (name, value) => {
  const encoded = JSON.stringify(value);
  try {
    await writeFile(join(directory, name), encoded, { flag: 'wx', mode: 0o600 });
  } catch (error) {
    if (error.code !== 'EEXIST') throw error;
    assert.equal(
      await readFile(join(directory, name), 'utf8'),
      encoded,
      'Original retirement input must be reconciled without replacement',
    );
  }
};
const { participantId, privacyDomainId } = await json(
  join(evidence, 'rpc-source-policy-input.json'),
);
if (mode === 'preflight') {
  const policy = transactionOperation('retention-policy').input.parse(
    await load('policy-input.json'),
  );
  assert.equal(policy.participantId, `urn:openpc:participant:${participantId}`);
  assert.equal(policy.policy.dataClass, 'ADMITTED_FACT');
  assert.equal(policy.policy.deletionMode, 'ROW_DELETE');
  const selected = storeRetirementPlanInput
    .omit({ retentionPolicyId: true })
    .parse(await load('selection-input.json'));
  const selection = retirementSelection.parse(
    parseRetirementWire(Buffer.from(selected.selectionWireHex, 'hex')),
  );
  assert.equal(selection.class, 'ADMITTED_FACT');
  assert.deepEqual(
    selection.rows.map((r) => r.candidate_id),
    selected.recordRefs.map((r) => r.candidateId),
  );
  const installed = await json(
    join(root, 'data/runtime-bootstrap/store-retirement/private/installation.json'),
  );
  assert.equal(selected.hostDigest, retirementWireDigest(installed.host));
  try {
    const document = admitStoreRetirement.parse(await load('admission-input.json'));
    const proposal = await load('admission-result-proposal.json');
    assert.deepEqual(
      projectApprovalCandidate({
        document,
        candidateDigest: proposal.candidateDigest,
        actionIntentId: document.actionIntentId,
        catalogOperationId: 'CFG-OP-ADMIT-STORE-RETIREMENT',
        resourceType: 'evidence-deletions',
        operationClass: 'CREATE',
      }),
      { candidate: document, redactedFields: [] },
    );
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  assert.deepEqual(installed.host.scope, {
    participant_id: participantId,
    privacy_domain_id: privacyDomainId,
  });
  process.stdout.write(
    'OPENPC_FACT_RETIREMENT_PREFLIGHT|PASS|actual-http-body|exact-selection|installed-scope\n',
  );
} else if (mode === 'plan') {
  const actors = await load('deployment-intent-actors.json');
  const selected = await load('selection-input.json');
  const policy = await load('policy-result.json');
  assert.equal(policy.state, 'SUCCEEDED');
  const input = { ...selected, retentionPolicyId: policy.resourceRef };
  await save('plan-input.json', input);
  const response = await fetch(
    `http://127.0.0.1:8080/api/v1/evidence-records/urn:openpc:resource:${selected.recordRefs[0].evidenceId}/store-retirement-plan`,
    {
      method: 'POST',
      signal: AbortSignal.timeout(15000),
      headers: {
        'Content-Type': 'application/json',
        'OpenPC-API-Version': '1',
        'Cookie': `__Host-openpc_session=${actors.maker.sessionToken}`,
        'OpenPC-Participant-ID': `urn:openpc:participant:${participantId}`,
        'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacyDomainId}`,
        'X-Request-ID': uuidv7(),
        'X-Correlation-ID': uuidv7(),
      },
      body: JSON.stringify(input),
    },
  );
  const result = await response.json();
  assert.equal(response.status, 200, `Retirement plan rejected: ${result.code ?? 'unknown'}`);
  await save('plan.json', storeRetirementPlan.parse(result));
  process.stdout.write(
    'OPENPC_FACT_RETIREMENT_PLAN|PASS|public-source-archive-and-policy-binding\n',
  );
} else if (mode === 'candidate') {
  const plan = storeRetirementPlan.parse(await load('plan.json'));
  const { actionIntentId, actionIntentDigest } = await load('admission-action.json');
  const { nativeSourceCheck: _check, ...binding } = plan;
  assert.equal(_check, 'REQUIRED_AT_ADMISSION');
  const body = admitStoreRetirement.parse({
    participantId: `urn:openpc:participant:${participantId}`,
    ...binding,
    previousAttemptId: null,
    actionIntentId,
    actionIntentDigest,
    reason:
      'Retire the original withdrawn and durably archived Fact payload while preserving its signed identity and lineage.',
  });
  await save('admission-input.json', body);
} else if (mode === 'api-selection') {
  await promisify(execFile)('bash', [
    'scripts/maintenance/run-bounded.sh',
    '--profile',
    'runtime-target',
    '--reuse',
    '--',
    'true',
  ]);
  const actors = await load('deployment-intent-actors.json');
  const selected = await load('selection-input.json');
  const policy = await load('policy-result.json');
  const terminal = await load('terminal-readback.json');
  const installed = await json(
    join(root, 'data/runtime-bootstrap/store-retirement/private/installation.json'),
  );
  const record = `urn:openpc:resource:${selected.recordRefs[0].evidenceId}`;
  const request = async (path, body, privacy = privacyDomainId) => {
    const response = await fetch(`http://127.0.0.1:8080/api/v1/${path}`, {
      method: body === undefined ? 'GET' : 'POST',
      signal: AbortSignal.timeout(15000),
      headers: {
        'Cookie': `__Host-openpc_session=${actors.maker.sessionToken}`,
        'OpenPC-API-Version': '1',
        'OpenPC-Participant-ID': `urn:openpc:participant:${participantId}`,
        'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacy}`,
        'X-Request-ID': uuidv7(),
        'X-Correlation-ID': uuidv7(),
        'Content-Type': 'application/json',
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    return { status: response.status, body: await response.json() };
  };
  const hosts = await request(`evidence-records/${record}/fact-retirement-hosts`);
  assert.equal(hosts.status, 200);
  assert.deepEqual(hosts.body, {
    items: [
      {
        hostDigest: selected.hostDigest,
        targetId: installed.host.target_id,
        store: 'openpc_facts',
      },
    ],
    authority: 'NONE',
  });
  const foreign = await request(
    `evidence-records/${record}/fact-retirement-hosts`,
    undefined,
    '018f0000-0000-7000-8000-000000000201',
  );
  assert.ok([403, 404].includes(foreign.status));
  assert.doesNotMatch(JSON.stringify(foreign.body), /hostDigest|targetId|items/u);
  const input = { hostDigest: selected.hostDigest, retentionPolicyId: policy.resourceRef };
  const retired = await request(`evidence-records/${record}/fact-retirement-plan`, input);
  assert.equal(retired.status, 412);
  assert.equal(retired.body.code, 'PC-DATA-6007');
  const supplied = await request(`evidence-records/${record}/fact-retirement-plan`, {
    ...input,
    selectionWireHex: selected.selectionWireHex,
    eligible: true,
  });
  assert.equal(supplied.status, 400);
  assert.equal(supplied.body.code, 'PC-DATA-6004');
  const original = await request(
    `evidence-deletions/store-retirements/attempts/${terminal.public.attemptId}`,
  );
  assert.equal(original.status, 200);
  assert.deepEqual(original.body, terminal.public);
  process.stdout.write(
    'OPENPC_FACT_RETIREMENT_SELECTION_API|PASS|authenticated-scoped-installed-hosts|foreign-disclosure-denied|retired-source-and-supplied-selection-denied|original-physical-outcome-unchanged\n',
  );
} else if (mode === 'selection') {
  await promisify(execFile)('bash', [
    'scripts/maintenance/run-bounded.sh',
    '--profile',
    'database',
    '--reuse',
    '--',
    'true',
  ]);
  const inspected = JSON.parse(
    (
      await promisify(execFile)('docker', [
        'inspect',
        'openpc-local-e2e-73ee9a9b7c3b-control-api-1',
      ])
    ).stdout,
  )[0];
  assert.equal(
    inspected.Config.Labels['com.docker.compose.project'],
    'openpc-local-e2e-73ee9a9b7c3b',
  );
  assert.equal(inspected.State.Running, false);
  for (const entry of inspected.Config.Env.filter((entry) => entry.startsWith('POLICY_FACT_'))) {
    const split = entry.indexOf('='),
      name = entry.slice(0, split),
      value = entry.slice(split + 1);
    if (name.endsWith('_FILE')) {
      const mount = inspected.Mounts.filter(
        (mount) => value === mount.Destination || value.startsWith(mount.Destination + '/'),
      ).sort((a, b) => b.Destination.length - a.Destination.length)[0];
      assert.ok(mount && mount.Type === 'bind' && mount.Source.startsWith(root + '/'));
      process.env[name] = mount.Source + value.slice(mount.Destination.length);
    } else process.env[name] = value;
  }
  process.env.POLICY_FACT_DATABASE_HOST = '127.0.0.1';
  process.env.POLICY_FACT_DATABASE_PORT = '55433';
  process.env.OPENPC_POLICY_FACT_READER_BIN = join(
    process.cwd(),
    'target/debug/policy_fact_reader',
  );
  const protectedRows = await load('protected-facts.json');
  assert.equal(protectedRows.length, 1);
  const live = protectedRows[0].value;
  const request = {
    participantId,
    privacyDomainId,
    candidateId: live.candidate_id,
    signedFactDigest: live.signed_fact_digest.slice(2),
  };
  const selected = await readFactRetirementSelection(request);
  assert.equal(selected.class, 'ADMITTED_FACT');
  assert.equal(selected.rows.length, 1);
  assert.equal(selected.fact_generation_id, live.generation_id);
  assert.equal(
    selected.rows[0].payload_digest,
    createHash('sha256')
      .update(Buffer.from(live.canonical_payload.slice(2), 'hex'))
      .digest('hex'),
  );
  assert.equal(selected.rows[0].payload_bytes, BigInt((live.canonical_payload.length - 2) / 2));
  assert.equal(selected.rows[0].signed_fact_digest, request.signedFactDigest);
  const original = (await load('original-fact.json'))[0].value;
  for (const altered of [
    { ...request, signedFactDigest: '0'.repeat(64) },
    { ...request, privacyDomainId: '018f0000-0000-7000-8000-000000000201' },
    {
      ...request,
      candidateId: original.candidate_id,
      signedFactDigest: original.signed_fact_digest.slice(2),
    },
  ])
    await assert.rejects(readFactRetirementSelection(altered), /PC-DATA-6007/u);
  const readerUser = process.env.POLICY_FACT_DATABASE_USER;
  const readerPasswordFile = process.env.POLICY_FACT_DATABASE_PASSWORD_FILE;
  try {
    process.env.POLICY_FACT_DATABASE_USER = 'openpc_facts';
    process.env.POLICY_FACT_DATABASE_PASSWORD_FILE = join(root, 'secrets/fact_pg_password.txt');
    await assert.rejects(readFactRetirementSelection(request), /PC-DATA-6007/u);
  } finally {
    process.env.POLICY_FACT_DATABASE_USER = readerUser;
    process.env.POLICY_FACT_DATABASE_PASSWORD_FILE = readerPasswordFile;
  }
  const facts = new Pool({
    host: '127.0.0.1',
    port: 55433,
    database: 'openpc_facts',
    user: 'openpc_facts',
    password: (await readFile(join(root, 'secrets/fact_pg_password.txt'), 'utf8')).trim(),
    max: 1,
    options: '-c default_transaction_read_only=on',
  });
  try {
    const scope = [participantId, privacyDomainId, original.candidate_id];
    const actual = await facts.query(
      `select a.fact_id::text,a.delta_sequence::text,g.canonical_generation::text,r.source_profile_id,r.source_generation_id,r.partition_id::text,r.candidate_sequence::text,r.checkpoint_digest,l.provenance_digest from facts.canonical_identity_allocation a join facts.canonical_generation g on g.participant_id=a.participant_id and g.privacy_domain_id=a.privacy_domain_id and g.fact_profile_id=a.fact_profile_id and g.generation_id=a.generation_id join facts.candidate_feed_receipt r on r.candidate_id=a.candidate_id and r.participant_id=a.participant_id and r.privacy_domain_id=a.privacy_domain_id join facts.fact_lineage l on l.candidate_id=a.candidate_id and l.participant_id=a.participant_id and l.privacy_domain_id=a.privacy_domain_id where a.participant_id=$1 and a.privacy_domain_id=$2 and a.candidate_id=$3`,
      [participantId, privacyDomainId, live.candidate_id],
    );
    assert.equal(actual.rowCount, 1);
    const row = actual.rows[0];
    assert.equal(selected.canonical_generation, BigInt(row.canonical_generation));
    assert.equal(selected.rows[0].fact_id, row.fact_id);
    assert.equal(selected.rows[0].fact_delta_sequence, BigInt(row.delta_sequence));
    assert.equal(selected.rows[0].candidate_feed_sequence, BigInt(row.candidate_sequence));
    assert.equal(selected.rows[0].checkpoint_digest, row.checkpoint_digest.toString('hex'));
    assert.equal(selected.rows[0].lineage_digest, row.provenance_digest.toString('hex'));
    assert.equal(selected.source.profile_id, row.source_profile_id);
    assert.equal(selected.source.generation_id, row.source_generation_id);
    assert.equal(selected.source.partition_id, row.partition_id);
    assert.deepEqual(
      (
        await facts.query(
          'select to_jsonb(f) value from facts.canonical_fact f where participant_id=$1 and privacy_domain_id=$2 and candidate_id<>$3 order by candidate_id',
          scope,
        )
      ).rows,
      protectedRows,
    );
    assert.equal(
      (
        await facts.query(
          'select 1 from facts.canonical_fact where participant_id=$1 and privacy_domain_id=$2 and candidate_id=$3',
          scope,
        )
      ).rowCount,
      0,
    );
    process.stdout.write(
      'OPENPC_FACT_RETIREMENT_SELECTION|PASS|native-read-only-signed-source|exact-allocation-and-checkpoint|tamper-and-scope-denied|retired-payload-unavailable|protected-successor-unchanged|authority=NONE\n',
    );
  } finally {
    await facts.end();
  }
} else if (mode === 'recovery') {
  await promisify(execFile)('bash', [
    'scripts/maintenance/run-bounded.sh',
    '--profile',
    'database',
    '--reuse',
    '--',
    'true',
  ]);
  const terminal = await load('terminal-readback.json');
  assert.ok(BigInt(terminal.public.dispatchNotAfterMs) < BigInt(Date.now()));
  const attempt = retirementAttempt.parse(
    parseRetirementWire(Buffer.from(terminal.attemptWire, 'hex')),
  );
  assert.deepEqual(attempt.scope, {
    participant_id: participantId,
    privacy_domain_id: privacyDomainId,
  });
  const privateRoot = join(root, 'data/runtime-bootstrap/store-retirement/private');
  const installed = await json(join(privateRoot, 'installation.json'));
  const original = await load('original-fact.json');
  assert.equal(original.length, 1);
  assert.equal(original[0].value.candidate_id, attempt.selection.rows[0].candidate_id);
  const readback = () =>
    new Promise((resolve, reject) => {
      const child = execFile(
        join(privateRoot, 'fact_retirement_owner'),
        [],
        {
          env: {
            ...process.env,
            OPENPC_RETIREMENT_FACT_CONFIGURATION_FILE: join(privateRoot, 'target.json'),
          },
          timeout: 20000,
          maxBuffer: 2098176,
          encoding: 'buffer',
        },
        (error, stdout) => {
          if (error) reject(new Error('Original native retirement readback unavailable'));
          else {
            try {
              resolve(parseFactRetirementTarget(stdout, installed.host, true));
            } catch (error) {
              reject(error);
            }
          }
        },
      );
      child.stdin.on('error', reject);
      child.stdin.end(retirementWireBytes({ mode: 'READBACK', attempt }));
    });
  assert.equal((await readback()).toString('hex'), terminal.signedOutcome);
  const facts = new Pool({
    host: '127.0.0.1',
    port: 55433,
    database: 'openpc_facts',
    user: 'openpc_facts',
    password: (await readFile(join(root, 'secrets/fact_pg_password.txt'), 'utf8')).trim(),
    max: 1,
    connectionTimeoutMillis: 5000,
    query_timeout: 10000,
  });
  try {
    const client = await facts.connect();
    try {
      await client.query('begin');
      await client.query('set local role openpc_facts_lifecycle_owner');
      await client.query(
        "select set_config('openpc.participant_id',$1,true),set_config('openpc.privacy_domain_id',$2,true)",
        [participantId, privacyDomainId],
      );
      await assert.rejects(
        client.query(
          'insert into facts.canonical_fact select * from jsonb_populate_record(null::facts.canonical_fact,$1::jsonb)',
          [JSON.stringify(original[0].value)],
        ),
        (error) =>
          error.code === '23505' &&
          error.schema === 'facts' &&
          error.table === 'retained_fact_identity' &&
          error.constraint === 'retained_fact_identity_pkey',
      );
    } finally {
      await client.query('rollback');
      client.release();
    }
    const scope = [participantId, privacyDomainId, attempt.selection.rows[0].candidate_id];
    assert.equal(
      (
        await facts.query(
          'select 1 from facts.canonical_fact where participant_id=$1 and privacy_domain_id=$2 and candidate_id=$3',
          scope,
        )
      ).rowCount,
      0,
    );
    assert.deepEqual(
      (
        await facts.query(
          'select to_jsonb(f) value from facts.signed_fact_custody f where participant_id=$1 and privacy_domain_id=$2 and candidate_id=$3 order by candidate_id',
          scope,
        )
      ).rows,
      await load('original-custody.json'),
    );
    assert.deepEqual(
      (
        await facts.query(
          'select to_jsonb(f) value from facts.canonical_fact f where participant_id=$1 and privacy_domain_id=$2 and candidate_id<>$3 order by candidate_id',
          scope,
        )
      ).rows,
      await load('protected-facts.json'),
    );
    assert.equal((await readback()).toString('hex'), terminal.signedOutcome);
    process.stdout.write(
      'OPENPC_FACT_RETIREMENT_RECOVERY|PASS|expired-dispatch-native-readback|exact-original-rebuild-denied-by-retained-identity|signed-outcome-and-custody-unchanged\n',
    );
  } finally {
    await facts.end();
  }
} else if (mode === 'verify' || mode === 'verify-restart') {
  await promisify(execFile)('bash', [
    'scripts/maintenance/run-bounded.sh',
    '--profile',
    'runtime-target',
    '--reuse',
    '--',
    'true',
  ]);
  const pool = async (port, database, file) =>
    new Pool({
      host: '127.0.0.1',
      port,
      database,
      user: database,
      max: 1,
      connectionTimeoutMillis: 5000,
      query_timeout: 10000,
      options: '-c default_transaction_read_only=on',
      password: (await readFile(join(root, 'secrets', file), 'utf8')).trim(),
    });
  const control = await pool(55432, 'openpc_control', 'control_pg_password.txt');
  const facts = await pool(55433, 'openpc_facts', 'fact_pg_password.txt');
  try {
    const admitted = await load('admission-result.json');
    assert.equal(admitted.state, 'SUCCEEDED');
    const actors = await load('deployment-intent-actors.json');
    const headers = {
      'OpenPC-API-Version': '1',
      'Cookie': `__Host-openpc_session=${actors.maker.sessionToken}`,
      'OpenPC-Participant-ID': `urn:openpc:participant:${participantId}`,
      'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacyDomainId}`,
      'X-Request-ID': uuidv7(),
      'X-Correlation-ID': uuidv7(),
    };
    const url = `http://127.0.0.1:8080/api/v1/evidence-deletions/store-retirements/attempts/${admitted.resourceRef}`;
    let publicResult;
    const recovering = mode === 'verify-restart';
    for (let attempt = 0; attempt < (recovering ? 40 : 1); attempt++) {
      const response = await fetch(url, { headers, signal: AbortSignal.timeout(15000) });
      publicResult = await publicReadResponse(response, recovering);
      if (publicResult !== null) break;
      if (attempt === 0)
        process.stdout.write(
          'OPENPC_FACT_RESTART_READBACK|WAIT|classified-unavailable|original-read-only\n',
        );
      await delay(250);
    }
    assert.ok(publicResult, 'Original retirement readback did not recover after restart');
    assert.equal(publicResult.physicalState, 'APPLIED');
    const foreign = await fetch(url, {
      headers: {
        ...headers,
        'OpenPC-Privacy-Domain-ID':
          'urn:openpc:privacy-domain:018f0000-0000-7000-8000-000000000201',
      },
      signal: AbortSignal.timeout(15000),
    });
    assert.ok([403, 404].includes(foreign.status));
    const denied = await foreign.text();
    assert.doesNotMatch(denied, /signedWire|attemptId|outcomeDigest|sourceBinding/u);
    const scope = [participantId, privacyDomainId],
      attemptId = admitted.resourceRef.slice(-36);
    const records = await control.query(
      `select a.attempt_wire,o.signed_wire,h.target_spki,h.host_wire
      from control.store_retirement_admission a join control.store_retirement_outcome o using(participant_id,privacy_domain_id,attempt_id)
      join control.store_retirement_host h on h.participant_id=a.participant_id and h.privacy_domain_id=a.privacy_domain_id and h.host_digest=a.host_digest
      where a.participant_id=$1 and a.privacy_domain_id=$2 and a.attempt_id=$3`,
      [...scope, attemptId],
    );
    assert.equal(records.rowCount, 1);
    const record = records.rows[0],
      attempt = retirementAttempt.parse(parseRetirementWire(record.attempt_wire));
    const verified = verifyRetirementOutcome(
      record.signed_wire,
      createPublicKey({ key: record.target_spki, format: 'der', type: 'spki' }),
      parseRetirementWire(record.host_wire),
      attempt,
    );
    assert.equal(verified.outcome.effect.state, 'APPLIED');
    const candidateId = attempt.selection.rows[0].candidate_id;
    const snapshot = async (table, comparison) =>
      (
        await facts.query(
          `select to_jsonb(f) value from facts.${table} f where participant_id=$1 and privacy_domain_id=$2 and candidate_id${comparison}$3 order by candidate_id`,
          [...scope, candidateId],
        )
      ).rows;
    assert.deepEqual(await snapshot('canonical_fact', '='), []);
    assert.deepEqual(await snapshot('canonical_fact', '<>'), await load('protected-facts.json'));
    assert.deepEqual(
      await snapshot('signed_fact_custody', '='),
      await load('original-custody.json'),
    );
    const target = await facts.query(
      'select signed_outcome from facts.store_retirement_attempt where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3',
      [...scope, attemptId],
    );
    assert.equal(target.rowCount, 1);
    assert.deepEqual(target.rows[0].signed_outcome, record.signed_wire);
    const identity = await facts.query(
      `select a.fact_id::text,a.delta_sequence::text,r.payload_digest,r.generation_id from facts.canonical_identity_allocation a join facts.retained_fact_identity r using(candidate_id,participant_id,privacy_domain_id,generation_id) where a.participant_id=$1 and a.privacy_domain_id=$2 and a.candidate_id=$3`,
      [...scope, candidateId],
    );
    assert.equal(identity.rowCount, 1);
    assert.equal(identity.rows[0].fact_id, attempt.selection.rows[0].fact_id);
    assert.equal(
      identity.rows[0].delta_sequence,
      String(attempt.selection.rows[0].fact_delta_sequence),
    );
    assert.equal(
      identity.rows[0].payload_digest.toString('hex'),
      attempt.selection.rows[0].payload_digest,
    );
    await save('terminal-readback.json', {
      public: publicResult,
      signedOutcome: record.signed_wire.toString('hex'),
      attemptWire: record.attempt_wire.toString('hex'),
    });
    process.stdout.write(
      'OPENPC_FACT_PHYSICAL_RETIREMENT|PASS|native-signed-outcome|public-readback|foreign-denial|payload-absent|original-cose-and-identity|protected-successor-unchanged\n',
    );
  } finally {
    await control.end();
    await facts.end();
  }
} else {
  await promisify(execFile)('bash', [
    'scripts/maintenance/run-bounded.sh',
    '--profile',
    'database',
    '--reuse',
    '--',
    'true',
  ]);
  const connect = async (port, database, passwordFile) =>
    new Pool({
      host: '127.0.0.1',
      port,
      database,
      user: database,
      password: (await readFile(join(root, 'secrets', passwordFile), 'utf8')).trim(),
      options: '-c default_transaction_read_only=on',
      max: 1,
      connectionTimeoutMillis: 5000,
      query_timeout: 10000,
    });
  const control = await connect(55432, 'openpc_control', 'control_pg_password.txt');
  const facts = await connect(55433, 'openpc_facts', 'fact_pg_password.txt');
  try {
    const { candidateId } = await json(join(evidence, 'rpc-acquisition/candidate.json'));
    const scope = [participantId, privacyDomainId];
    const rows = (
      await facts.query(
        `select f.candidate_id,f.generation_id,f.canonical_payload,f.signed_fact_digest,f.cose_sign1,
      a.fact_id,a.delta_sequence::text,g.canonical_generation::text,r.candidate_sequence::text,
      r.source_profile_id,r.source_generation_id,r.partition_id,r.checkpoint_digest,l.provenance_digest,closed.material,closed.material_digest
      from facts.canonical_fact f join facts.canonical_identity_allocation a using(candidate_id,participant_id,privacy_domain_id,generation_id)
      join facts.canonical_generation g on g.participant_id=a.participant_id and g.privacy_domain_id=a.privacy_domain_id and g.fact_profile_id=a.fact_profile_id and g.generation_id=a.generation_id
      join facts.candidate_feed_receipt r on r.candidate_id=f.candidate_id and r.participant_id=f.participant_id and r.privacy_domain_id=f.privacy_domain_id
      join facts.fact_lineage l on l.candidate_id=f.candidate_id and l.participant_id=f.participant_id and l.privacy_domain_id=f.privacy_domain_id
      join facts.source_checkpoint c on c.participant_id=f.participant_id and c.privacy_domain_id=f.privacy_domain_id and c.source_profile_id=r.source_profile_id
      join facts.readiness_gate ready on ready.participant_id=f.participant_id and ready.privacy_domain_id=f.privacy_domain_id and ready.generation_id=f.generation_id
      join facts.withdrawal_checkpoint closed on closed.participant_id=f.participant_id and closed.privacy_domain_id=f.privacy_domain_id and closed.partition_id=r.partition_id and closed.source_profile_id=r.source_profile_id and closed.source_generation_id=r.source_generation_id
      where f.participant_id=$1 and f.privacy_domain_id=$2 and f.candidate_id=$3 and f.state='RETIRED'
        and f.complete and f.finality_verified and f.finalized_at is not null and c.state='COMPLETE'
        and ready.state='STALE' and not ready.shard_verified`,
        [...scope, candidateId],
      )
    ).rows;
    assert.equal(rows.length, 1, 'Original terminal Fact with complete checkpoint is required');
    const row = rows[0];
    assert.deepEqual(createHash('sha256').update(row.material).digest(), row.material_digest);
    const provenance = JSON.parse(row.material.toString('utf8'));
    const publication = provenance.publicationDigest;
    assert.match(publication, /^sha256:[0-9a-f]{64}$/u);
    assert.equal(
      createHash('sha256').update(row.cose_sign1).digest('hex'),
      row.signed_fact_digest.toString('hex'),
    );
    const selection = retirementSelection.parse({
      class: 'ADMITTED_FACT',
      source: {
        profile_id: row.source_profile_id,
        generation_id: row.source_generation_id,
        partition_id: row.partition_id,
        identity_digest: publication.slice(7),
      },
      fact_generation_id: row.generation_id,
      canonical_generation: BigInt(row.canonical_generation),
      rows: [
        {
          candidate_id: candidateId,
          fact_id: row.fact_id,
          fact_delta_sequence: BigInt(row.delta_sequence),
          candidate_feed_sequence: BigInt(row.candidate_sequence),
          payload_digest: createHash('sha256').update(row.canonical_payload).digest('hex'),
          payload_bytes: BigInt(row.canonical_payload.length),
          signed_fact_digest: row.signed_fact_digest.toString('hex'),
          lineage_digest: row.provenance_digest.toString('hex'),
          checkpoint_digest: row.checkpoint_digest.toString('hex'),
        },
      ],
    });
    const custody = (
      await control.query(
        `select c.evidence_id from control.evidence_catalogue c join control.evidence_fact_provenance p using(participant_id,privacy_domain_id,stream_id,record_id)
      where c.participant_id=$1 and c.privacy_domain_id=$2 and p.projection->>'candidateId'=$3 and c.receipt_digest=$4`,
        [...scope, candidateId, `sha256:${selection.rows[0].signed_fact_digest}`],
      )
    ).rows;
    assert.equal(custody.length, 1);
    const pins = await json(
      join(root, 'data/runtime-bootstrap/store-retirement/private/installation.json'),
    );
    assert.deepEqual(pins.host.scope, {
      participant_id: participantId,
      privacy_domain_id: privacyDomainId,
    });
    await save('selection-input.json', {
      hostDigest: retirementWireDigest(pins.host),
      selectionWireHex: retirementWireBytes(selection).toString('hex'),
      recordRefs: [{ candidateId, evidenceId: custody[0].evidence_id }],
    });
    const actionIntentId = 'ACT-EVIDENCE_DELETIONS_ADMIT_STORE_BATCH-V1';
    const action = await control.query(
      "select 'sha256:'||encode(semantic_digest,'hex') digest from control.action_intent where action_intent_id=$1 and maker_checker_required and step_up_required and idempotency_required",
      [actionIntentId],
    );
    assert.equal(action.rowCount, 1);
    await save('admission-action.json', {
      actionIntentId,
      actionIntentDigest: action.rows[0].digest,
    });
    await save(
      'policy-input.json',
      transactionCandidate(
        'retention-policy',
        transactionFields('retention-policy', {
          dataClass: 'ADMITTED_FACT',
          policyVersion: '1.0.0',
          retentionPeriodMs: '0',
          localGraceMs: '0',
          sinkQuorum: '1',
          deletionMode: 'ROW_DELETE',
          makerCheckerRequired: 'true',
        }),
        'Preserve durable Fact custody and signed history while permitting governed retirement of terminal payloads.',
        participantId,
      ).body,
    );
    const snapshot = async (sql) => (await facts.query(sql, [...scope, candidateId])).rows;
    await save(
      'original-fact.json',
      await snapshot(
        'select to_jsonb(f) value from facts.canonical_fact f where participant_id=$1 and privacy_domain_id=$2 and candidate_id=$3',
      ),
    );
    await save(
      'protected-facts.json',
      await snapshot(
        'select to_jsonb(f) value from facts.canonical_fact f where participant_id=$1 and privacy_domain_id=$2 and candidate_id<>$3 order by candidate_id',
      ),
    );
    await save(
      'original-custody.json',
      await snapshot(
        'select to_jsonb(f) value from facts.signed_fact_custody f where participant_id=$1 and privacy_domain_id=$2 and candidate_id=$3',
      ),
    );
    process.stdout.write(
      'OPENPC_FACT_RETIREMENT_INPUTS|PASS|actual-terminal-selection|original-cose|protected-successor|governance=REQUIRED\n',
    );
  } finally {
    await control.end();
    await facts.end();
  }
}
