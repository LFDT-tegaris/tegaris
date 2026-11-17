import { signFixtureCertificate } from './fixture-certificate.mjs';
import { verifyIssuedWorkloadCertificate } from '../../../services/identity-service/src/domain/workload-credential-issuer.ts';
import assert from 'node:assert/strict';
import { readFile, writeFile, mkdir, chmod, cp } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { X509Certificate } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { prepareRpcJournalCrashFixture } from './rpc-journal-crash-fixture.mjs';
import { planRpcEnospcRuntime, rpcEnospcCompose } from './rpc-journal-enospc-runtime.mjs';
const { Pool } = createRequire(join(process.cwd(), 'package.json'))('pg');
const { uuidv7 } = await import(
  join(process.cwd(), 'services/control-api/src/configuration/governed-mutation-http.ts')
);
async function immutableFile(path, bytes, mode = 0o444) {
  try {
    assert.deepEqual(await readFile(path), Buffer.from(bytes), 'owned fixture changed');
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    await writeFile(path, bytes, { mode, flag: 'wx' });
  }
}
const root = process.argv[2];
assert.ok(root?.startsWith('/'));
const pid = '018f0000-0000-7000-8000-000000000101',
  privacy = '018f0000-0000-7000-8000-000000007201';
const principal = '018f0000-0000-7000-8000-000000008190',
  credential = '018f0000-0000-7000-8000-000000008192';
const secrets = join(root, 'secrets'),
  data = join(root, 'data'),
  evidence = join(root, 'evidence/runtime-bootstrap');
const owned = join(data, 'runtime-bootstrap'),
  runtime = join(owned, 'runtime');
const actors = JSON.parse(await readFile(join(evidence, 'deployment-intent-actors.json'), 'utf8'));
const pool = new Pool({
  host: '127.0.0.1',
  port: 55432,
  database: 'openpc_control',
  user: 'openpc_control',
  password: (await readFile(join(secrets, 'control_pg_password.txt'), 'utf8')).trim(),
  max: 1,
});
try {
  assert.equal(
    (
      await pool.query(
        "select count(*)::int n from control.module_installation where participant_id=$1 and privacy_domain_id=$2 and state='ENABLED'",
        [pid, privacy],
      )
    ).rows[0].n,
    15,
  );
  assert.equal(
    (
      await pool.query(
        'select count(*)::int n from control.policy_generation where participant_id=$1 and privacy_domain_id=$2',
        [pid, privacy],
      )
    ).rows[0].n,
    0,
  );
  const api = async (path, body, key) => {
    const headers = {
      'Cookie': `__Host-openpc_session=${actors.maker.sessionToken}`,
      'OpenPC-API-Version': '1',
      'OpenPC-Participant-ID': `urn:openpc:participant:${pid}`,
      'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacy}`,
      'X-Request-ID': uuidv7(),
      'X-Correlation-ID': uuidv7(),
    };
    if (body) {
      const csrf = await fetch('http://127.0.0.1:8080/api/v1/session/csrf', {
        method: 'POST',
        headers: {
          ...headers,
          'origin': 'http://127.0.0.1:8080',
          'content-type': 'application/json',
        },
        body: JSON.stringify({ actionIntentId: body.actionIntentId }),
      });
      assert.equal(csrf.status, 200);
      Object.assign(headers, {
        'X-CSRF-Token': (await csrf.json()).csrfToken,
        'origin': 'http://127.0.0.1:8080',
        'content-type': 'application/json',
        'Idempotency-Key': key,
        'X-OpenPC-Action-Intent-Digest': body.actionIntentDigest,
      });
    }
    const response = await fetch(`http://127.0.0.1:8080/api/v1/${path}`, {
      method: body ? 'POST' : 'GET',
      headers,
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
    const result = await response.json();
    assert.equal(
      response.status,
      body ? 202 : 200,
      `public ${path}: ${result.code ?? result.error?.code ?? response.status}`,
    );
    return result;
  };
  const action = 'ACT-RUNTIME_TARGETS_CREATE_RESOURCE-V1',
    key = 'configuration-target-create-0001';
  const retained = (
    await pool.query(
      'select terminal_state,result_payload from control.idempotency_record where participant_id=$1 and privacy_domain_id=$2 and principal_id=$3 and action_intent_id=$4 and idempotency_key=$5',
      [pid, privacy, actors.maker.principalId, action, key],
    )
  ).rows;
  let operation;
  if (retained.length) {
    assert.equal(retained.length, 1);
    assert.equal(retained[0].terminal_state, 'COMMITTED');
    operation = await api(`operations/${retained[0].result_payload.operationId}`);
  } else {
    const digest = (
      await pool.query(
        "select 'sha256:'||encode(semantic_digest,'hex') digest from control.action_intent where action_intent_id=$1",
        [action],
      )
    ).rows[0].digest;
    operation = await api(
      'runtime-targets',
      {
        participantId: `urn:openpc:participant:${pid}`,
        actionIntentId: action,
        actionIntentDigest: digest,
        reason: 'Register an isolated target without activation authority.',
        desiredGenerationDigest: null,
        activeGenerationDigest: null,
        xdsVersionDigest: null,
        observedAt: '2026-09-10T00:00:00.000000Z',
      },
      key,
    );
  }
  assert.equal(operation.state, 'SUCCEEDED');
  await writeFile(join(evidence, 'configuration-target.json'), JSON.stringify(operation), {
    mode: 0o600,
  });
  const target = operation.resourceRef.split(':').at(-1);
  const targetView = await api(`runtime-targets/${operation.resourceRef}`);
  assert.equal(targetView.state, 'OFFLINE');
  for (const name of ['desiredGenerationDigest', 'activeGenerationDigest', 'xdsVersionDigest'])
    assert.equal(targetView[name], null);
  await writeFile(
    join(evidence, 'configuration-target-resource.json'),
    JSON.stringify(targetView),
    { mode: 0o600 },
  );
  // Initial trust establishes only the separate machine principal. The public
  // issuance owner below must create its credential and all governed effects.
  await pool.query('begin');
  await pool.query(
    "select openpc.set_request_context('PARTICIPANT',$1,$2,uuidv7(),'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',true)",
    [pid, privacy],
  );
  await pool.query(
    "insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch) values($1,$2,'WORKLOAD','Isolated runtime bootstrap target','ACTIVE',1) on conflict do nothing",
    [principal, pid],
  );
  const machine = (
    await pool.query(
      'select participant_id::text,kind,state,display_label from control.principal where principal_id=$1',
      [principal],
    )
  ).rows;
  assert.deepEqual(machine, [
    {
      participant_id: pid,
      kind: 'WORKLOAD',
      state: 'ACTIVE',
      display_label: 'Isolated runtime bootstrap target',
    },
  ]);
  await pool.query('commit');
  for (const path of [
    owned,
    runtime,
    join(runtime, 'tls'),
    join(runtime, 'trust'),
    join(owned, 'provider-probe-source'),
    join(owned, 'provider-probe-journal'),
  ]) {
    await mkdir(path, { recursive: true });
    await chmod(path, 0o777);
  }
  for (const file of [
    'protected-server.pem',
    'protected-server.key',
    'workload-ca.pem',
    'ads-ca.pem',
  ])
    await immutableFile(
      join(runtime, 'tls', file),
      await readFile(
        file === 'ads-ca.pem'
          ? join(secrets, 'runtime_ads_ca.pem')
          : join(data, 'runtime/tls', file),
      ),
    );
  await immutableFile(
    join(runtime, 'trust/fleet-bootstrap.pub'),
    await readFile(join(data, 'runtime/trust/fleet-bootstrap.pub')),
  );
  const privateKey = join(runtime, 'tls/ads-client.key'),
    issued = join(runtime, 'tls/issuer-certificate.pem');
  const exists = async (path) =>
    readFile(path).then(
      () => true,
      (e) => {
        if (e.code === 'ENOENT') return false;
        throw e;
      },
    );
  if (!(await exists(privateKey))) {
    execFileSync(
      'openssl',
      [
        'req',
        '-new',
        '-newkey',
        'ec',
        '-pkeyopt',
        'ec_paramgen_curve:P-256',
        '-nodes',
        '-subj',
        '/CN=OpenPC isolated target workload',
        '-addext',
        `subjectAltName=URI:urn:openpc:participant:${pid}:workload:${target}`,
        '-addext',
        'extendedKeyUsage=clientAuth',
        '-keyout',
        privateKey,
        '-out',
        join(runtime, 'tls/ads-client.csr'),
      ],
      { stdio: 'ignore' },
    );
  }
  if (!(await exists(issued))) {
    signFixtureCertificate(
      join(runtime, 'tls/ads-client.csr'),
      join(secrets, 'identity_mtls_ca.pem'),
      join(secrets, 'identity_mtls_ca_key.pem'),
      issued,
    );
  }
  await chmod(privateKey, 0o444);
  const certificate = new X509Certificate(await readFile(issued));
  assert.equal(certificate.subjectAltName, `URI:urn:openpc:participant:${pid}:workload:${target}`);
  assert.ok(Date.parse(certificate.validTo) > Date.now() + 600000);
  const entry = {
    credentialId: credential,
    participantId: pid,
    principalId: principal,
    workloadId: `urn:openpc:workload:${target}`,
    publicKeySpkiDer: Buffer.from(
      certificate.publicKey.export({ type: 'spki', format: 'der' }),
    ).toString('base64'),
    certificateDer: certificate.raw.toString('base64'),
  };
  assert.ok(
    verifyIssuedWorkloadCertificate(
      certificate.raw,
      await readFile(join(secrets, 'identity_mtls_ca.pem')),
      { ...entry, publicKeySpkiDer: Buffer.from(entry.publicKeySpkiDer, 'base64') },
    ),
    'Discovery fixture certificate must satisfy the real issuer verifier before approval',
  );
  const manifest = JSON.parse(await readFile(join(data, 'workload-issuer-manifest.json'), 'utf8'));
  assert.equal(
    manifest.some((v) => v.credentialId === credential),
    false,
  );
  await immutableFile(
    join(owned, 'workload-issuer-manifest.json'),
    JSON.stringify([...manifest, entry]),
  );
  const input = {
    participantId: pid,
    privacyDomainId: privacy,
    principalId: principal,
    credentialId: credential,
    targetId: target,
    privateKeyPath: privateKey,
    certificateOutput: join(runtime, 'tls/ads-client.pem'),
    rpcJournalEnospc: await planRpcEnospcRuntime(root, target),
  };
  await writeFile(join(evidence, 'discovery-credential-input.json'), JSON.stringify(input), {
    mode: 0o600,
    flag: 'wx',
  });
  const keys = JSON.parse(
    await readFile(join(secrets, 'runtime_analysis_target_keys.json'), 'utf8'),
  );
  keys[target] = (
    await readFile(join(secrets, 'runtime_agent_projection_public_key.txt'), 'utf8')
  ).trim();
  await immutableFile(join(owned, 'runtime-analysis-target-keys.json'), JSON.stringify(keys));
  await cp(join(data, 'rpc-provider'), join(owned, 'rpc-provider'), {
    recursive: true,
    errorOnExist: true,
    force: false,
  });
  const providerAddress = process.argv[3];
  assert.match(providerAddress, /^\d+(\.\d+){3}$/u);
  const volumes = [
    `${join(owned, 'provider-probe-source')}:/provider-sources:ro`,
    `${runtime}:/runtime`,
  ];
  await prepareRpcJournalCrashFixture(runtime);
  const enospc = rpcEnospcCompose(input.rpcJournalEnospc);
  const compose = {
    'x-openpc-rpc-enospc': enospc.extension,
    'volumes': enospc.volumes,
    'services': {
      'control-worker': {
        environment: {
          CONTROL_WORKER_PRIVACY_DOMAIN_ID: privacy,
          OPENPC_MANAGED_DEPLOYMENT_ENABLED: 'false',
          CONTROL_WORKER_DEPLOYMENT_TARGET_ID: target,
          CONTROL_WORKER_ADS_CLIENT_CA_FILE: '/run/secrets/identity_mtls_ca',
          OPENPC_INDEXER_MANAGER_DATABASE_URL_FILE: '/fact-manager-url',
        },
        volumes: [
          ...volumes,
          `${join(owned, 'provider-probe-journal')}:/provider-journal`,
          `${join(owned, 'fact-bridge/manager-url')}:/fact-manager-url:ro`,
        ],
      },
      'runtime-envoy': { volumes: [`${runtime}:/runtime:ro`] },
      'runtime-target': {
        environment: {
          OPENPC_TARGET_RUNTIME_ID: target,
          OPENPC_TARGET_BOOTSTRAP_DIRECTORY: `/runtime/target-bootstrap/${target}`,
          LD_PRELOAD: '/runtime/rpc-journal-crash-fixture.so',
          OPENPC_RPC_JOURNAL_FAULT_DIRECTORY: `/runtime/evidence/${target}`,
          ...enospc.targetEnvironment,
        },
        volumes: [...volumes, enospc.targetMount],
      },
      'rpc-provider': {
        environment: {
          OPENPC_RPC_READ_CONTRACT_ADDRESS: process.env.OPENPC_RPC_READ_CONTRACT_ADDRESS,
        },
        networks: { 'openpc-local': { ipv4_address: providerAddress } },
        volumes: [`${join(owned, 'rpc-provider')}:/provider`],
      },
      'fact-service': {
        environment: { OPENPC_FACT_BRIDGE_CONFIGURATION_FILE: '/fact-bridge/deployment.json' },
        volumes: [
          `${owned}/fact-bridge/config:/fact-bridge:ro`,
          `${owned}/fact-bridge/connections:/fact-connections`,
          `${owned}/fact-bridge/artifacts:/fact-artifacts`,
          `${owned}/provider-probe-source:/provider-sources:ro`,
        ],
      },
    },
    'secrets': {
      runtime_analysis_target_keys: { file: join(owned, 'runtime-analysis-target-keys.json') },
    },
  };
  await writeFile(join(owned, 'compose.json'), JSON.stringify(compose), { mode: 0o600 });
  process.stdout.write(
    'OPENPC_BOOTSTRAP_DISCOVERY_PREPARE|PASS|public-target-OFFLINE|no-generation|new-machine-initial-trust|isolated-files\n',
  );
} finally {
  await pool.query('rollback').catch(() => {});
  await pool.end();
}
