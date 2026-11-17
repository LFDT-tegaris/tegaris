import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import {
  createECDH,
  createPrivateKey,
  createPublicKey,
  ECDH,
  generateKeyPairSync,
  randomBytes,
} from 'node:crypto';
import { mkdir, readFile, readdir, stat, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { promisify } from 'node:util';
import { Pool } from 'pg';
import { z } from 'zod';
import {
  installStoreRetirementHost,
  validateStoreRetirementInstallation,
} from '../../../services/control-api/src/evidence/store-retirement-installation.ts';
import {
  retirementHost,
  retirementWireDigest,
} from '../../../services/control-api/src/evidence/store-retirement-wire.ts';

// Installation trust only. No source selection, approval, attempt, admission or
// business effect is created here. Retained pins are never silently replaced.
const exec = promisify(execFile);
const candidate = process.argv[2] === '--candidate';
const args = process.argv.slice(candidate ? 3 : 2);
const [root, participantId, privacyDomainId, targetId, factKeyId] = args;
assert.equal(args.length, candidate ? 4 : 5);
const store = candidate ? 'openpc_candidate_index' : 'openpc_facts';
assert.equal(resolve(root), root);
for (const id of [participantId, privacyDomainId, targetId]) z.uuidv7().parse(id);
if (!candidate) assert.match(factKeyId, /^sha256:[0-9a-f]{64}$/u);
assert.match(
  await readFile(join(root, '.openpc-local-runtime-owner'), 'utf8'),
  /^openpc-local-runtime:/u,
);
await exec('bash', [
  'scripts/maintenance/run-bounded.sh',
  '--profile',
  'database',
  '--reuse',
  '--',
  'true',
]);
const host = retirementHost.parse({
  environment_id: 'local',
  target_id: targetId,
  scope: { participant_id: participantId, privacy_domain_id: privacyDomainId },
  store,
});
const directory = join(
  root,
  'data/runtime-bootstrap',
  candidate ? 'candidate-store-retirement' : 'store-retirement',
);
const source = join(directory, 'private');
const published = join(directory, 'api');
const mounted = candidate ? '/app/candidate-store-retirement' : '/app/store-retirement';
const secrets = join(root, 'secrets');
await mkdir(source, { recursive: true, mode: 0o700 });
await mkdir(published, { recursive: true, mode: 0o755 });
const pool = new Pool({
  host: '127.0.0.1',
  port: 55432,
  database: 'openpc_control',
  user: 'openpc_control',
  password: (await readFile(join(secrets, 'control_pg_password.txt'), 'utf8')).trim(),
  max: 1,
  connectionTimeoutMillis: 5000,
  query_timeout: 10000,
});
const privateBytes = async (name) => {
  const path = join(source, name),
    info = await stat(path);
  assert.equal(info.isFile(), true);
  assert.equal(info.mode & 0o077, 0);
  return readFile(path);
};
const put = (name, value) => writeFile(join(source, name), value, { mode: 0o600, flag: 'wx' });
const compressed = (key) => {
  const jwk = key.export({ format: 'jwk' });
  return ECDH.convertKey(
    Buffer.concat([
      Buffer.from([4]),
      Buffer.from(jwk.x, 'base64url'),
      Buffer.from(jwk.y, 'base64url'),
    ]),
    'prime256v1',
    undefined,
    undefined,
    'compressed',
  );
};
try {
  const names = await readdir(source);
  if (names.length === 0) {
    assert.equal(
      (
        await pool.query(
          'select count(*)::text count from control.store_retirement_host where participant_id=$1 and privacy_domain_id=$2 and host_digest=$3',
          [participantId, privacyDomainId, retirementWireDigest(host)],
        )
      ).rows[0].count,
      '0',
      'Existing installation requires its original private pins',
    );
    const credential = await pool.query(
      `select credential_epoch::text epoch,
      floor(extract(epoch from valid_from)*1000)::text valid_from_ms,
      floor(extract(epoch from valid_until)*1000)::text valid_until_ms
      from control.credential where participant_id=$1 and credential_id=$2 and kind='WORKLOAD_MTLS'
      and state='ACTIVE' and valid_from<=clock_timestamp() and valid_until>clock_timestamp()`,
      [participantId, '018f0000-0000-7000-8000-000000000198'],
    );
    assert.equal(credential.rowCount, 1);
    const control = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const target = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const metadata = {
      host,
      workloadCredentialId: '018f0000-0000-7000-8000-000000000198',
      workloadCredentialEpoch: credential.rows[0].epoch,
      validFromMs: Number(credential.rows[0].valid_from_ms),
      validUntilMs: Number(credential.rows[0].valid_until_ms),
      databaseRole: 'openpc_local_control_worker',
      installationReference: `local-store-retirement:${retirementWireDigest(host)}`,
    };
    const capability = (
      await readFile(
        join(
          secrets,
          candidate ? 'candidate_retirement_capability_secret.txt' : 'fact_capability_secret.txt',
        ),
        'utf8',
      )
    ).trim();
    assert.match(capability, /^[0-9a-f]{64}$/u);
    const factPublic = candidate
      ? undefined
      : await readFile(join(secrets, 'policy_fact_verify_key.sec1'));
    if (factPublic) assert.equal(factPublic.length, 33);
    const password = (
      await readFile(
        join(
          secrets,
          candidate ? 'indexer_writer_db_password.txt' : 'fact_runtime_db_password.txt',
        ),
        'utf8',
      )
    ).trim();
    assert.match(password, /^\S{32,256}$/u);
    await put('control.pem', control.privateKey.export({ format: 'pem', type: 'pkcs8' }));
    await put(
      'target.hex',
      Buffer.from(target.privateKey.export({ format: 'jwk' }).d, 'base64url').toString('hex'),
    );
    await put('verifier.key', randomBytes(32));
    await put('capability.hex', capability);
    await put('fact-password', password);
    if (factPublic) await put('fact.sec1', factPublic);
    await put(
      'target.json',
      JSON.stringify({
        host,
        authority: {
          version: 1,
          host,
          control_public_key_sec1: [...compressed(control.publicKey)],
          target_public_key_sec1: [...compressed(target.publicKey)],
        },
        targetSigningKeyFile: join(source, 'target.hex'),
        capabilitySecretFile: join(source, 'capability.hex'),
        ...(candidate
          ? {}
          : { factVerifyKeyFile: join(source, 'fact.sec1'), factVerifyKeyId: factKeyId }),
        database: {
          host: '127.0.0.1',
          port: candidate ? 55434 : 55433,
          name: store,
          user: candidate ? 'openpc_indexer_writer' : 'openpc_fact_runtime',
          passwordFile: join(source, 'fact-password'),
        },
      }),
    );
    // Written last. A partial preparation is retained and must be reconciled,
    // never overwritten with fresh keys after a potentially ambiguous install.
    await put('installation.json', JSON.stringify(metadata));
  }
  const metadata = JSON.parse(await privateBytes('installation.json'));
  assert.deepEqual(metadata.host, host);
  const control = createPrivateKey(await privateBytes('control.pem'));
  const native = JSON.parse(await privateBytes('target.json'));
  assert.deepEqual(native.host, host);
  if (!candidate) assert.equal(native.factVerifyKeyId, factKeyId);
  assert.deepEqual(native.authority.control_public_key_sec1, [
    ...compressed(createPublicKey(control)),
  ]);
  const target = createPublicKey({
    key: {
      kty: 'EC',
      crv: 'P-256',
      x: ECDH.convertKey(
        Buffer.from(native.authority.target_public_key_sec1),
        'prime256v1',
        undefined,
        undefined,
        'uncompressed',
      )
        .subarray(1, 33)
        .toString('base64url'),
      y: ECDH.convertKey(
        Buffer.from(native.authority.target_public_key_sec1),
        'prime256v1',
        undefined,
        undefined,
        'uncompressed',
      )
        .subarray(33)
        .toString('base64url'),
    },
    format: 'jwk',
  });
  const derived = createECDH('prime256v1');
  derived.setPrivateKey(Buffer.from((await privateBytes('target.hex')).toString(), 'hex'));
  assert.deepEqual(
    [...derived.getPublicKey(undefined, 'compressed')],
    native.authority.target_public_key_sec1,
  );
  const verifier = await privateBytes('verifier.key');
  assert.equal(verifier.length, 32);
  const pins = validateStoreRetirementInstallation({
    ...metadata,
    controlSpki: createPublicKey(control).export({ format: 'der', type: 'spki' }),
    targetSpki: target.export({ format: 'der', type: 'spki' }),
    verifierSecret: verifier,
  });
  const image = JSON.parse(
    (await exec('docker', ['image', 'inspect', 'openpc-r1-dev/control-api:local'])).stdout,
  )[0];
  assert.equal(image.Config.Labels['io.openpc.image.owner'], 'openpc-r1-local-runtime-v1');
  assert.equal(image.Config.Labels['io.openpc.image.service'], 'control-api');
  assert.equal(image.Config.User, 'openpc');
  // The API receives only its admission verifier and, for candidate observation,
  // the read-only database credential. Target signing/capability bytes stay private.
  const files = [['verifier.key', verifier]];
  if (candidate) {
    const reader = await readFile(join(secrets, 'candidate_index_reader_db_password.txt'));
    assert.match(reader.toString().trim(), /^[0-9a-f]{64}$/u);
    files.push(['reader-password', reader]);
    files.push([
      'observer.json',
      Buffer.from(
        JSON.stringify({
          host,
          database: {
            host: 'candidate-index-pg',
            port: 5432,
            name: store,
            user: 'openpc_candidate_index_reader',
            passwordFile: `${mounted}/reader-password`,
          },
        }),
      ),
    ]);
  }
  // The constrained installer receives bytes on stdin, with no source-secret
  // mount or network, and preserves exact existing pins under the image user.
  const installer = `const fs=require('node:fs'),assert=require('node:assert/strict');
    const entry=fs.readFileSync('/etc/passwd','utf8').split('\\n').find(v=>v.startsWith('openpc:')).split(':');
    const uid=Number(entry[2]),gid=Number(entry[3]);assert.ok(uid>0&&gid>0);
    const name=process.argv[1];assert.ok(['verifier.key','reader-password','observer.json'].includes(name));
    const key=fs.readFileSync(0);assert.ok(key.length>0&&key.length<=65536);if(name==='verifier.key')assert.equal(key.length,32);const path='/installed/'+name;
    try {const s=fs.lstatSync(path);assert.ok(s.isFile());assert.equal(s.uid,uid);assert.equal(s.mode&511,256);assert.deepEqual(fs.readFileSync(path),key);}
    catch(e){if(e.code!=='ENOENT')throw e;fs.writeFileSync(path,key,{flag:'wx',mode:256});fs.chownSync(path,uid,gid);}
    key.fill(0);process.stdout.write('OPENPC_RETIREMENT_PRIVATE_MOUNT|PASS|actual-image-user|0400\\n');`;
  for (const [name, bytes] of files)
    await new Promise((done, reject) => {
      const child = execFile(
        'docker',
        [
          'run',
          '--rm',
          '-i',
          '--network',
          'none',
          '--read-only',
          '--user',
          '0:0',
          '--cap-drop',
          'ALL',
          '--cap-add',
          'CHOWN',
          '--cap-add',
          'DAC_OVERRIDE',
          '--security-opt',
          'no-new-privileges',
          '--memory',
          '64m',
          '--memory-swap',
          '64m',
          '--cpus',
          '0.25',
          '--pids-limit',
          '32',
          '--mount',
          `type=bind,src=${published},dst=/installed`,
          '--entrypoint',
          'node',
          image.Id,
          '-e',
          installer,
          name,
        ],
        { timeout: 15000, maxBuffer: 4096 },
        (error, stdout) => {
          if (error) reject(new Error('Private verifier publication failed; retain original pins'));
          else {
            process.stdout.write(stdout);
            done();
          }
        },
      );
      child.stdin.on('error', reject);
      child.stdin.end(bytes);
    });
  const original = candidate
    ? JSON.parse(
        await readFile(
          join(root, 'data/runtime-bootstrap/store-retirement/api/admissions.json'),
          'utf8',
        ),
      ).hosts
    : [];
  if (candidate) {
    assert.equal(original.length, 1);
    assert.equal(original[0].host.store, 'openpc_facts');
    assert.deepEqual(original[0].host.scope, host.scope);
    assert.equal(original[0].verifierKeyFile, '/app/store-retirement/verifier.key');
  }
  const admissions = JSON.stringify({
    hosts: [
      ...original,
      {
        host,
        verifierKeyFile: `${mounted}/verifier.key`,
        ...(candidate ? { targetConfigurationFile: `${mounted}/observer.json` } : {}),
      },
    ],
  });
  try {
    await writeFile(join(published, 'admissions.json'), admissions, { flag: 'wx', mode: 0o444 });
  } catch (error) {
    if (error.code !== 'EEXIST') throw error;
    assert.equal(await readFile(join(published, 'admissions.json'), 'utf8'), admissions);
  }
  await exec(
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
      '64m',
      '--memory-swap',
      '64m',
      '--cpus',
      '0.25',
      '--pids-limit',
      '32',
      '--mount',
      `type=bind,src=${published},dst=${mounted},readonly`,
      '--entrypoint',
      'node',
      image.Id,
      '-e',
      `const fs=require('node:fs'),assert=require('node:assert/strict');assert.ok(process.getuid()>0);const c=JSON.parse(fs.readFileSync('${mounted}/admissions.json'));const h=c.hosts.at(-1),p=h.verifierKeyFile;assert.equal(fs.statSync(p).mode&511,256);assert.equal(fs.readFileSync(p).length,32);
      if(h.host.store==='openpc_candidate_index') {
        assert.deepEqual(fs.readdirSync('${mounted}').sort(),['admissions.json','observer.json','reader-password','verifier.key']);
        const config=JSON.parse(fs.readFileSync(h.targetConfigurationFile));assert.deepEqual(Object.keys(config).sort(),['database','host']);assert.deepEqual(config.host,h.host);
        assert.equal(config.database.user,'openpc_candidate_index_reader');assert.equal(config.database.name,'openpc_candidate_index');
        for(const file of [h.targetConfigurationFile,config.database.passwordFile])assert.equal(fs.statSync(file).mode&511,256);
        assert.match(fs.readFileSync(config.database.passwordFile,'utf8').trim(),/^[0-9a-f]{64}$/);
      }`,
    ],
    { timeout: 15000, maxBuffer: 4096 },
  );
  const result = await installStoreRetirementHost(pool, pins);
  for (const [, bytes] of files) bytes.fill(0);
  process.stdout.write(
    `OPENPC_RETIREMENT_INSTALLATION|PASS|${result.state}|host=${result.hostDigest}|business-effects=NONE\n`,
  );
} finally {
  await pool.end();
}
