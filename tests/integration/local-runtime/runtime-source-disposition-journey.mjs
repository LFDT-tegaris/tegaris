// Real source import/archive/public readback helpers for the ordinary journey.
// This driver never writes database business state or fabricates native custody.
import assert from 'node:assert/strict';
import { continueRuntimeSourceArchive } from './runtime-source-disposition-archive.mjs';
import {
  runtimeSourceSigningFamilies,
  runtimeSourceSigningProfiles,
} from './runtime-source-disposition-signing.ts';
import { createHash } from 'node:crypto';
import { execFile, execFileSync } from 'node:child_process';
import { chmod, mkdir, readFile, realpath, rename, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';
import { Pool } from 'pg';
import {
  sourceScope,
  runtimeArchiveConfiguration,
  verifyRuntimeSourceContainer,
} from './runtime-source-bootstrap.mjs';
import {
  runtimeArtifactDispositionPlan,
  runtimeArtifactDispositionView,
} from '../../../services/control-api/src/evidence/runtime-artifact-disposition-contract.ts';
import { activateRetentionPolicy } from '../../../services/control-api/src/evidence/retention-contracts.ts';
import { configurationMutationOperation } from '../../../packages/security-kernel/src/configuration-operations.ts';
import {
  createIndexerProfileSchema,
  createProjectionPlanSchema,
} from '../../../services/control-api/src/configuration/resource-contracts.ts';

export function sourceDispositionInputPreflight() {
  assert.deepEqual(
    runtimeSourceSigningFamilies
      .flatMap(({ family }) => runtimeSourceSigningProfiles(family))
      .map((p) => p.catalogOperationId)
      .sort(),
    [
      'CFG-OP-ACTIVATE-RETENTION-POLICY',
      'CFG-OP-DELETE-RUNTIME-ARTIFACT-BATCH',
      'CFG-OP-DISPOSE-RUNTIME-ARTIFACT-SOURCE',
      'CFG-OP-RETIRE-RETENTION-POLICY',
    ],
  );
  const operation = configurationMutationOperation('CFG-OP-DISPOSE-RUNTIME-ARTIFACT-SOURCE');
  assert.equal(operation.actionIntentId, 'ACT-EVIDENCE_DELETIONS_DISPOSE_RUNTIME_SOURCE-V1');
  assert.equal(operation.makerCheckerRequired, true);
  assert.equal(operation.stepUpRequired, true);
  assert.equal(operation.resourceType, 'evidence-deletions');
  const initial = JSON.parse(
    execFileSync(
      process.execPath,
      [
        '--import',
        'tsx',
        'tests/integration/local-runtime/deployment-intent-actors.mjs',
        'preflight-only',
        'preflight-only',
        sourceScope.participant,
        'bootstrap-runtime-context',
        sourceScope.privacy,
        '018f0000-0000-7000-8000-000000000201',
        '--preflight',
      ],
      { encoding: 'utf8', timeout: 15000 },
    ),
  );
  assert.ok(initial.privacyDomainIds.includes(sourceScope.privacy));
  for (const action of [
    operation.actionIntentId,
    'ACT-EVIDENCE_DELETIONS_READ_RUNTIME_SOURCE-V1',
    'ACT-EVIDENCE_DELETIONS_CREATE_RUNTIME_BATCH-V1',
    'ACT-EVIDENCE_DELETIONS_READ_RESOURCE-V1',
    'ACT-RETENTION_POLICIES_CREATE_RESOURCE-V1',
    'ACT-RETENTION_POLICIES_READ_RESOURCE-V1',
  ])
    assert.ok(initial.actions.includes(action));
  activateRetentionPolicy.parse({
    participantId: `urn:openpc:participant:${sourceScope.participant}`,
    predecessorPolicyId: null,
    actionIntentId: 'ACT-RETENTION_POLICIES_CREATE_RESOURCE-V1',
    actionIntentDigest: `sha256:${'1'.repeat(64)}`,
    reason: 'Retain a real archived runtime source.',
    policy: {
      dataClass: 'RUNTIME_ARTIFACT',
      policyVersion: '1.0.0',
      retentionPeriodMs: '0',
      localGraceMs: '0',
      sinkQuorum: 1,
      deletionMode: 'ROW_DELETE',
      makerCheckerRequired: true,
    },
  });
}

async function observeDispositionEffect(database, admission) {
  const {
    rows: [effect],
  } = await database.query(
    `select
  (select count(*)::int from control.runtime_artifact_source_disposition where participant_id=$1 and privacy_domain_id=$2 and disposition_id=$3 and operation_id=$4) dispositions,
  (select count(*)::int from control.idempotency_record where participant_id=$1 and privacy_domain_id=$2 and operation_id=$4 and idempotency_key=$5) operations,
  (select count(*)::int from control.receipt_signing_attempt where participant_id=$1 and privacy_domain_id=$2 and operation_id=$4) attempts,
  (select jsonb_agg(jsonb_build_object('id',receipt_id,'digest',encode(receipt_digest,'hex'),'cbor',encode(receipt_cbor,'hex'),'signature',encode(cose_sign1,'hex')) order by receipt_id) from control.audit_occurrence where participant_id=$1 and privacy_domain_id=$2 and operation_id=$4) receipts,
  (select jsonb_agg(jsonb_build_object('id',event_id,'receipt',receipt_id,'payload',encode(payload_cbor,'hex'),'digest',encode(payload_digest,'hex'),'signature',encode(cose_sign1,'hex')) order by event_id) from control.outbox_event where participant_id=$1 and privacy_domain_id=$2 and aggregate_id=$3 and event_type='io.openpc.control.command.committed.v1' and proof_kind='BUSINESS_RECEIPT_REFERENCE' and sequence_namespace='CONTROL_BUSINESS_TRANSITION_V1') events`,
    [
      sourceScope.participant,
      sourceScope.privacy,
      admission.resourceRef.slice(-36),
      admission.operationId,
      admission.idempotencyKey,
    ],
  );
  assert.equal(effect.dispositions, 1);
  assert.equal(effect.operations, 1);
  assert.equal(effect.attempts, 1);
  assert.equal(effect.receipts.length, 1);
  assert.equal(effect.events.length, 1);
  assert.equal(effect.events[0].receipt, effect.receipts[0].id);
  return effect;
}

const [mode, root, composeText, ...args] = process.argv.slice(2);
if (mode === '--preflight' || mode === '--native-preflight') sourceDispositionInputPreflight();
if (mode === '--preflight') {
  assert.equal(root, undefined);
  process.stdout.write(
    'OPENPC_RUNTIME_SOURCE_DISPOSITION_PREFLIGHT|PASS|actual-profile|retention|public-selection\n',
  );
} else if (mode === '--effect-preflight') {
  assert.equal(composeText, undefined);
  const database = new Pool({
    host: '127.0.0.1',
    port: 55432,
    database: 'openpc_control',
    user: 'openpc_control',
    password: (await readFile(join(root, 'secrets/control_pg_password.txt'), 'utf8')).trim(),
    max: 1,
  });
  try {
    const admission = JSON.parse(
      await readFile(
        join(root, 'evidence/runtime-bootstrap/runtime-source-disposition/admission.json'),
      ),
    );
    await observeDispositionEffect(database, admission);
    process.stdout.write(
      'OPENPC_RUNTIME_SOURCE_DISPOSITION_PREFLIGHT|PASS|actual-committed-effect|same-receipt-outbox-signing-attempt\n',
    );
  } finally {
    await database.end();
  }
} else if (mode === '--native-preflight') {
  assert.equal(composeText, undefined);
  const execute = promisify(execFile);
  const inspected = JSON.parse(
    (await execute('docker', ['image', 'inspect', root], { maxBuffer: 1048576 })).stdout,
  )[0];
  assert.equal(inspected.Config.Labels['io.openpc.image.owner'], 'openpc-r1-local-runtime-v1');
  assert.equal(inspected.Config.Labels['io.openpc.image.service'], 'control-worker');
  const indexer = '018f0000-0000-7000-8000-000000008182',
    projection = '018f0000-0000-7000-8000-000000008183';
  const fixtures = [];
  for (const plan of ['-', projection]) {
    const result = await execute(
      'docker',
      [
        'run',
        '--rm',
        '--network',
        'none',
        '--read-only',
        '--cap-drop',
        'ALL',
        '--security-opt',
        'no-new-privileges',
        '--memory',
        '128m',
        '--memory-swap',
        '128m',
        '--cpus',
        '0.5',
        '--pids-limit',
        '64',
        '-e',
        'OPENPC_LOCAL_RUNTIME=1',
        '-e',
        `OPENPC_LOCAL_FIXTURE_SCOPE=${JSON.stringify([sourceScope.participant, sourceScope.privacy])}`,
        inspected.Id,
        'local-fixture',
        '-',
        indexer,
        plan,
        '-',
      ],
      { timeout: 30000, maxBuffer: 1048576 },
    );
    const fixture = JSON.parse(result.stdout),
      bytes = Buffer.from(fixture.configurationCborHex, 'hex');
    assert.equal(
      fixture.configurationDigest,
      `sha256:${createHash('sha256').update(bytes).digest('hex')}`,
    );
    const action = {
      reason: 'Prepare the exact runtime source input.',
      actionIntentDigest: `sha256:${'1'.repeat(64)}`,
    };
    createIndexerProfileSchema.parse({
      ...action,
      actionIntentId: 'ACT-INDEXER_PROFILES_CREATE_RESOURCE-V1',
      participantId: `urn:openpc:participant:${sourceScope.participant}`,
      engine: 'CLIENT_INDEXER',
      engineVersion: '1.0.0',
      methodProfileDigest: fixture.indexerArtifactDigest,
    });
    createProjectionPlanSchema.parse({
      ...action,
      actionIntentId: 'ACT-PROJECTION_PLANS_CREATE_RESOURCE-V1',
      indexerProfileId: `urn:openpc:resource:${indexer}`,
      planDigest: fixture.projectionArtifactDigest,
      readiness: 'UNKNOWN',
    });
    fixtures.push(fixture);
  }
  assert.notEqual(fixtures[0].configurationDigest, fixtures[1].configurationDigest);
  for (const key of ['indexerArtifactDigest', 'projectionArtifactDigest'])
    assert.equal(fixtures[0][key], fixtures[1][key]);
  process.stdout.write(
    'OPENPC_RUNTIME_SOURCE_DISPOSITION_PREFLIGHT|PASS|packaged-native-fixtures|actual-public-input-schemas|distinct-source-versions\n',
  );
} else {
  assert.equal(await realpath(root), root);
  const compose = JSON.parse(composeText);
  assert.deepEqual(compose.slice(0, 2), ['docker', 'compose']);
  const execute = promisify(execFile);
  const run = async (command, argv) =>
    (await execute(command, argv, { timeout: 45000, maxBuffer: 20 * 1024 * 1024 })).stdout;
  const container = (service) =>
    run(compose[0], [...compose.slice(1), 'ps', '-q', service]).then((v) => v.trim());
  const json = async (path) => JSON.parse(await readFile(path, 'utf8'));
  const sourceCase = process.env.OPENPC_RUNTIME_SOURCE_DISPOSITION_CASE ?? 'original';
  assert.ok(['original', 'live-replay'].includes(sourceCase));
  const evidence = join(root, 'evidence/runtime-bootstrap'),
    originalOutput = join(evidence, 'runtime-source-disposition'),
    output = sourceCase === 'original' ? originalOutput : join(originalOutput, sourceCase);
  const priorInputs = sourceCase === 'original' ? 0 : 2;
  const archiveFile = sourceCase === 'original' ? 'archive.json' : 'archive-live-replay.json';
  await mkdir(output, { recursive: true, mode: 0o700 });
  const save = async (name, value) =>
    writeFile(join(output, `${name}.json`), JSON.stringify(value), { flag: 'wx', mode: 0o600 });
  const worker = await container('control-worker');
  const [inspected] = JSON.parse(await run('docker', ['inspect', worker]));
  const config = await json(join(root, 'data/runtime-source-config/configuration.json'));
  const owner = (await readFile(join(root, '.openpc-local-runtime-owner'), 'utf8'))
    .trim()
    .split(':');
  verifyRuntimeSourceContainer(inspected, { root, project: owner[1], config });
  assert.deepEqual(config.archive_custody, runtimeArchiveConfiguration);
  const database = new Pool({
    host: '127.0.0.1',
    port: 55432,
    database: 'openpc_control',
    user: 'openpc_control',
    password: (await readFile(join(root, 'secrets/control_pg_password.txt'), 'utf8')).trim(),
    max: 1,
    statement_timeout: 3000,
    query_timeout: 5000,
  });
  const rows = async () =>
    (
      await database.query(
        `select i.runtime_configuration_input_id::text id,'sha256:'||encode(i.configuration_digest,'hex') digest,
    i.selected,c.active,i.module_configuration_generation_id::text generation from control.runtime_configuration_input i
    join control.module_configuration_generation c on c.generation_id=i.module_configuration_generation_id
    where i.participant_id=$1 and i.privacy_domain_id=$2 order by i.created_at,i.runtime_configuration_input_id`,
        [sourceScope.participant, sourceScope.privacy],
      )
    ).rows;
  const journal = async () => {
    const original = await run('docker', [
      'exec',
      worker,
      'cat',
      '/runtime-source-journal/owner/runtime-artifact-source.json',
    ]);
    const state = JSON.parse(original);
    const records = state.history.originals.map((wire) => ({
      wire,
      observation: JSON.parse(Buffer.from(wire).toString()).claims.observation,
    }));
    return { original, records, entries: state.entries };
  };
  const until = async (observe) => {
    for (let n = 0; n < 120; n++) {
      const value = await observe();
      if (value) return value;
      await delay(250);
    }
    throw new Error(`Runtime source ${mode} readback did not converge`);
  };
  try {
    if (mode === 'fixture') {
      const [name, indexer, projection = '-'] = args;
      assert.match(name, /^[a-z-]+$/u);
      const fixture = JSON.parse(
        await run('docker', [
          'exec',
          '-e',
          `OPENPC_LOCAL_FIXTURE_SCOPE=${JSON.stringify([sourceScope.participant, sourceScope.privacy])}`,
          worker,
          '/usr/local/bin/openpc-control-worker',
          'local-fixture',
          '-',
          indexer,
          projection,
          '-',
        ]),
      );
      const bytes = Buffer.from(fixture.configurationCborHex, 'hex');
      assert.equal(
        fixture.configurationDigest,
        `sha256:${createHash('sha256').update(bytes).digest('hex')}`,
      );
      await save(name, fixture);
    } else if (mode === 'import') {
      const [name] = args;
      assert.ok(['old', 'successor'].includes(name));
      const fixture = await json(join(output, `${name}.json`)),
        bytes = Buffer.from(fixture.configurationCborHex, 'hex');
      const before = await rows();
      assert.equal(before.length, priorInputs + (name === 'old' ? 0 : 1));
      assert.ok(before.every((v) => v.digest !== fixture.configurationDigest));
      const path = join(
        root,
        'data/runtime-bootstrap/provider-probe-source/runtime-configuration.cbor',
      );
      await writeFile(`${path}.next`, bytes, { mode: 0o444, flag: 'wx' });
      await rename(`${path}.next`, path);
      const current = await until(async () => {
        const values = await rows();
        return values.length === before.length + 1 &&
          values.filter((v) => v.selected).length === 1 &&
          values.find((v) => v.selected)?.digest === fixture.configurationDigest
          ? values
          : null;
      });
      assert.ok(current.every((v) => v.active === true));
      const source = current.find((v) => v.digest === fixture.configurationDigest);
      const native = await until(async () => {
        const native = await journal();
        return native.records.some((r) => r.observation.ImportCommitted?.input_id === source.id)
          ? native
          : null;
      });
      await save(`${name}-import`, {
        source,
        originals: native.records.filter(
          (r) =>
            r.observation.ImportPending?.input_id === source.id ||
            r.observation.ImportCommitted?.input_id === source.id,
        ),
      });
      if (name === 'successor')
        assert.ok(current.filter((v) => v.id !== source.id).every((v) => !v.selected));
    } else if (mode === 'archive') {
      const source = (await json(join(output, 'old-import.json'))).source;
      const directory = join(root, 'data/runtime-source-vault');
      await mkdir(directory, { recursive: true, mode: 0o777 });
      await chmod(directory, 0o777);
      const archive = {
        database: {
          host: 'control-pg',
          port: 5432,
          database: 'openpc_control',
          user: config.database_role.replace('openpc_rs_login_', 'openpc_ra_login_'),
          passwordFile: runtimeArchiveConfiguration.database_password_file,
        },
        vaultDirectory: '/runtime-source-vault/owner',
        sinkId: 'runtime-source-local-vault',
        scopes: [
          {
            participantId: sourceScope.participant,
            privacyDomainId: sourceScope.privacy,
            streamId: runtimeArchiveConfiguration.stream_id,
            source: 'RUNTIME_ARTIFACT',
            runtimeArtifact: {
              participantId: sourceScope.participant,
              privacyDomainId: sourceScope.privacy,
              runtimeConfigurationInputId: source.id,
            },
            activeKeyId: 'runtime-source-archive-key',
            keys: [
              {
                keyId: 'runtime-source-archive-key',
                keyFile: runtimeArchiveConfiguration.keys['runtime-source-archive-key'],
              },
            ],
            retentionSeconds: 60,
            capacityBytes: 8388608,
          },
        ],
      };
      const path = join(root, 'data/runtime-source-config', archiveFile);
      await writeFile(path, JSON.stringify(archive), { flag: 'wx', mode: 0o444 });
      const networks = Object.keys(inspected.NetworkSettings.Networks);
      assert.equal(networks.length, 1);
      const [api] = JSON.parse(await run('docker', ['inspect', await container('control-api')]));
      await run('docker', [
        'run',
        '--rm',
        '--name',
        `${owner[1]}-runtime-archive`,
        '--label',
        `com.docker.compose.project=${owner[1]}`,
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
        '-e',
        'OPENPC_RUNTIME_ARTIFACT_SOURCE_SOCKET_DIRECTORY=/run/openpc-runtime-source',
        '-v',
        `${root}/data/runtime-source-config:/runtime-source-config:ro`,
        '-v',
        `${root}/runtime-source-archive:/runtime-source-archive:ro`,
        '-v',
        `${root}/data/runtime-source-ipc:/run/openpc-runtime-source:ro`,
        '-v',
        `${directory}:/runtime-source-vault`,
        '--entrypoint',
        'node',
        api.Image,
        '/app/evidence-worker.mjs',
        '--once',
      ]);
      const native = await until(async () => {
        const v = await journal();
        return v.records.some(
          (r) => r.observation.ArchiveCustodyCommitted?.input.input_id === source.id,
        )
          ? v
          : null;
      });
      await save(
        'archive-native',
        native.records.filter(
          (r) => r.observation.ArchiveCustodyCommitted?.input.input_id === source.id,
        ),
      );
      await continueRuntimeSourceArchive(root, compose, database, sourceCase);
    } else if (mode === 'effect') {
      const [phase] = args;
      assert.ok(['before-replay', 'after-replay'].includes(phase));
      const admission = await json(join(output, 'admission.json'));
      const effect = await observeDispositionEffect(database, admission);
      if (phase === 'after-replay')
        assert.deepEqual(effect, await json(join(output, 'before-replay.json')));
      await save(phase, effect);
      process.stdout.write(
        `OPENPC_RUNTIME_SOURCE_DISPOSITION|PASS|${phase}|one-effect|same-receipt-outbox-signing-attempt\n`,
      );
    } else if (mode === 'plan') {
      const [which, policyId] = args;
      assert.ok(['old', 'successor'].includes(which));
      const source = (await json(join(output, `${which}-import.json`))).source;
      const actors = await json(join(evidence, 'deployment-intent-actors.json'));
      const response = await fetch(
        'http://127.0.0.1:8080/api/v1/evidence-deletions/runtime-sources/plan',
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Cookie': `__Host-openpc_session=${actors.maker.sessionToken}`,
            'OpenPC-API-Version': '1',
            'OpenPC-Participant-ID': `urn:openpc:participant:${sourceScope.participant}`,
            'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${sourceScope.privacy}`,
            'X-Request-ID': source.id,
            'X-Correlation-ID': source.id,
          },
          body: JSON.stringify({
            runtimeConfigurationInputId: `urn:openpc:resource:${source.id}`,
            retentionPolicyId: policyId,
          }),
        },
      );
      const body = await response.json();
      assert.equal(
        response.status,
        200,
        response.status === 200 ? undefined : JSON.stringify(body),
      );
      const plan = runtimeArtifactDispositionPlan.parse(body);
      if (which === 'old') {
        assert.deepEqual(plan.blockers, []);
        assert.equal(plan.selection.observation.source.runtimeConfigurationInputId, source.id);
      } else {
        assert.equal(plan.selection, null);
        assert.deepEqual(plan.blockers, ['SELECTED_INPUT']);
      }
      try {
        const original = await json(join(output, `${which}-plan.json`));
        assert.deepEqual(plan, original, 'A retained plan must reconcile exactly');
      } catch (error) {
        if (error.code !== 'ENOENT') throw error;
        await save(`${which}-plan`, plan);
      }
    } else if (mode === 'verify' || mode === 'reconcile') {
      const [file] = args,
        view = runtimeArtifactDispositionView.parse(await json(file));
      const original = (await json(join(output, 'old-import.json'))).source;
      const admission = await json(join(output, 'admission.json'));
      assert.equal(admission.state, 'SUCCEEDED');
      assert.equal(admission.truthState, 'SUCCESS');
      assert.equal(view.dispositionId, admission.resourceRef);
      assert.equal(view.operationId, admission.operationId);
      assert.equal(view.runtimeConfigurationInputId, `urn:openpc:resource:${original.id}`);
      assert.equal(view.newUseState, 'DENIED');
      if (mode === 'verify') assert.equal(view.nativeState, 'DENIED');
      else assert.ok(['PENDING', 'DENIED'].includes(view.nativeState));
      assert.equal(view.physicalState, 'NOT_ESTABLISHED');
      const current = await rows();
      assert.equal(current.length, priorInputs + 2);
      assert.equal(current.find((v) => v.id === original.id).selected, false);
      assert.equal(current.filter((v) => v.selected).length, 1);
      assert.ok(current.every((v) => v.active));
      const { records, entries } = await journal();
      assert.equal(entries.length, priorInputs / 2 + 1);
      const targetEntries = entries.filter(
        (entry) => entry.denial.admission.disposition_id === admission.resourceRef.slice(-36),
      );
      assert.equal(targetEntries.length, 1);
      const retained = targetEntries[0];
      assert.equal(retained.denial.admission.disposition_id, admission.resourceRef.slice(-36));
      assert.equal(retained.denial.admission.operation_id, admission.operationId);
      assert.equal(
        `sha256:${retained.denial.admission.admission_receipt_digest}`,
        view.admissionReceiptDigest,
      );
      assert.ok(Array.isArray(retained.signed_denial) && retained.signed_denial.length > 0);
      if (view.nativeState === 'DENIED')
        assert.equal(
          view.nativeDenialDigest,
          `sha256:${createHash('sha256').update(Buffer.from(retained.signed_denial)).digest('hex')}`,
        );
      assert.equal(
        records.filter((r) => r.observation.ArchiveCustodyCommitted?.input.input_id === original.id)
          .length,
        1,
      );
      // Source history can advance for another business case. Its earlier
      // signed import/archive/denial records must remain byte-identical.
      for (const preservedOutput of sourceCase === 'original'
        ? [output]
        : [originalOutput, output]) {
        for (const name of ['old', 'successor']) {
          const imported = await json(join(preservedOutput, `${name}-import.json`));
          assert.deepEqual(
            current.find((v) => v.id === imported.source.id),
            {
              ...imported.source,
              selected: current.find((v) => v.id === imported.source.id)?.selected,
            },
          );
          for (const record of imported.originals) {
            const matched = records.filter(
              (v) => JSON.stringify(v.observation) === JSON.stringify(record.observation),
            );
            assert.equal(matched.length, 1);
            assert.deepEqual(matched[0].wire, record.wire);
          }
        }
        const archives = await json(join(preservedOutput, 'archive-native.json'));
        assert.equal(archives.length, 1);
        for (const record of archives) {
          const matched = records.filter(
            (v) => JSON.stringify(v.observation) === JSON.stringify(record.observation),
          );
          assert.equal(matched.length, 1);
          assert.deepEqual(matched[0].wire, record.wire);
        }
        const preservedAdmission = await json(join(preservedOutput, 'admission.json'));
        const matches = entries.filter(
          (entry) =>
            entry.denial.admission.disposition_id === preservedAdmission.resourceRef.slice(-36),
        );
        assert.equal(matches.length, 1);
        const denialPath = join(preservedOutput, 'denial-original.json');
        try {
          assert.deepEqual(matches[0], await json(denialPath));
        } catch (error) {
          if (error.code !== 'ENOENT') throw error;
          // A preceding completed case must have its baseline before new effects.
          assert.equal(preservedOutput, output);
          await writeFile(denialPath, JSON.stringify(matches[0]), { flag: 'wx', mode: 0o600 });
        }
      }
      process.stdout.write(
        `OPENPC_RUNTIME_SOURCE_DISPOSITION|PASS|public-admission|native=${view.nativeState}|same-signed-original|active-provenance|physical-not-established\n`,
      );
    } else throw new Error('Unknown runtime source journey phase');
  } finally {
    await database.end();
  }
}
