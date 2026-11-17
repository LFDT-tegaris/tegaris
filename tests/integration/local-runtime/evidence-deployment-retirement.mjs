import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { Pool } from 'pg';
import { uuidv7 } from '../../../services/control-api/src/configuration/governed-mutation-http.ts';
import { verifyDeploymentRetirementSource } from './evidence-deployment-retirement-checks.mjs';
import {
  projectionDeletionBrowser,
  projectionDeletionPreflight,
} from './evidence-projection-deletion-browser.mjs';

const exec = promisify(execFile);
await exec('bash', [
  'scripts/maintenance/run-bounded.sh',
  '--profile',
  'runtime-target',
  '--reuse',
  '--',
  'true',
]);
const [secretRoot, evidenceRoot, dataRoot, participantId, privacyDomainId, composeJson, mode] =
  process.argv.slice(2);
assert.ok(mode === undefined || mode === '--readback' || mode === '--resume-finalized');
const readback = mode === '--readback';
const resume = readback || mode === '--resume-finalized';
const compose = JSON.parse(composeJson);
assert.deepEqual(compose.slice(0, 2), ['docker', 'compose']);
const config = { host: '127.0.0.1', port: 55432, database: 'openpc_control', max: 1 };
const owner = async (user, file) =>
  new Pool({ ...config, user, password: (await readFile(join(secretRoot, file), 'utf8')).trim() });
const admin = await owner('openpc_control', 'control_pg_password.txt');
const worker = await owner('openpc_local_control_worker', 'control_worker_runtime_db_password.txt');
const runtime = await owner('openpc_configuration_runtime', 'control_api_runtime_db_password.txt');
const root = join(dataRoot, 'deployment-retirement');
const configuration = join(root, 'worker.json');
if (!resume) await mkdir(root, { mode: 0o700 });
const scope = resume
  ? JSON.parse(await readFile(configuration, 'utf8')).scopes[0]
  : { participantId, privacyDomainId, streamId: `deployment-effects-${uuidv7()}` };
assert.equal(scope.participantId, participantId);
assert.equal(scope.privacyDomainId, privacyDomainId);
try {
  const foreign = (
    await admin.query(
      "select privacy_domain_id::text id from control.privacy_domain where participant_id=$1 and privacy_domain_id<>$2 and state='ACTIVE' order by privacy_domain_id limit 1",
      [participantId, privacyDomainId],
    )
  ).rows[0]?.id;
  assert.ok(foreign);
  projectionDeletionPreflight(participantId, privacyDomainId, foreign);
  const container = (
    await exec(compose[0], [...compose.slice(1), 'ps', '-q', 'control-api'])
  ).stdout.trim();
  const running = JSON.parse((await exec('docker', ['inspect', container])).stdout)[0];
  const built = JSON.parse(
    (await exec('docker', ['image', 'inspect', 'openpc-r1-dev/control-api:local'])).stdout,
  )[0];
  assert.equal(running.Image, built.Id);
  assert.equal(built.Config.Labels['io.openpc.image.service'], 'control-api');
  for (const [source, destination] of [
    ['/app/evidence-worker.mjs', 'evidence-worker.mjs'],
    ['/app/result-source.sql', 'result-source.sql'],
    ['/usr/local/bin/openpc-policy-evaluator', 'openpc-policy-evaluator'],
  ])
    await exec('docker', ['cp', `${container}:${source}`, join(root, destination)]);
  await chmod(join(root, 'openpc-policy-evaluator'), 0o700);
  if (!resume) {
    await writeFile(join(root, 'encryption.key'), randomBytes(32), { mode: 0o600, flag: 'wx' });
    await writeFile(
      configuration,
      JSON.stringify({
        database: {
          ...config,
          max: undefined,
          user: 'openpc_local_control_worker',
          passwordFile: join(secretRoot, 'control_worker_runtime_db_password.txt'),
        },
        vaultDirectory: join(root, 'vault'),
        sinkId: `deployment-retirement-${uuidv7()}`,
        scopes: [
          {
            ...scope,
            source: 'EFFECT',
            activeKeyId: 'deployment-retirement',
            keys: [{ keyId: 'deployment-retirement', keyFile: join(root, 'encryption.key') }],
            retentionSeconds: 86400,
            capacityBytes: 16 * 1024 * 1024,
          },
        ],
      }),
      { mode: 0o600, flag: 'wx' },
    );
  }
  Object.assign(process.env, {
    OPENPC_POLICY_CORE_BIN: join(root, 'openpc-policy-evaluator'),
    OPENPC_DEPLOYMENT_PROJECTION_PUBLIC_KEY_FILE: join(
      secretRoot,
      'runtime_agent_projection_public_key.txt',
    ),
    OPENPC_DEPLOYMENT_REJECTION_PUBLIC_KEY_FILE: join(
      secretRoot,
      'fleet_deployment_rejection_public_key.txt',
    ),
    OPENPC_EVIDENCE_WORKER_CONFIG_FILE: configuration,
  });
  const sources = (
    await admin.query(
      'select count(*)::int n from control.deployment_result where participant_id=$1 and privacy_domain_id=$2',
      [participantId, privacyDomainId],
    )
  ).rows[0].n;
  assert.ok(sources > 1 && sources <= 512);
  for (let tick = 0; tick <= sources; tick++) {
    await exec(process.execPath, [join(root, 'evidence-worker.mjs'), '--once'], {
      env: process.env,
      timeout: 30000,
      maxBuffer: 65536,
    });
    const recorded = (
      await admin.query(
        'select count(*)::int n from control.evidence_catalogue where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3',
        [participantId, privacyDomainId, scope.streamId],
      )
    ).rows[0].n;
    if (recorded === sources) break;
    assert.ok(tick < sources, 'bounded real-source custody drain');
  }
  await verifyDeploymentRetirementSource({
    admin,
    runtime,
    worker,
    scope,
    requireClosed: !readback,
    requireReorg: readback,
  });
  process.stdout.write(
    `OPENPC_DEPLOYMENT_RETIREMENT_INPUT|configuration=${configuration}|source=${readback ? 'actual-later-reorg' : 'actual-finalized-checkpoint'}\n`,
  );
  await projectionDeletionBrowser({
    secretRoot,
    evidenceRoot,
    dataRoot,
    compose,
    participantId,
    privacyDomainId,
    deploymentConfiguration: configuration,
    deploymentReadback: readback,
    deploymentResumeFinalized: mode === '--resume-finalized',
  });
} finally {
  await runtime.end();
  await worker.end();
  await admin.end();
}
