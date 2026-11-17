import { tmpdir } from 'node:os';
import assert from 'node:assert/strict';
import test from 'node:test';
import {
  readRuntimeRetirementApprovalChain,
  requireNewRetirementObservation,
} from './runtime-source-retirement-recovery-state.mjs';
import {
  rpcRetirementSigningFamilies,
  rpcRetirementSigningWorkload,
  rpcRetirementSigningProfiles,
  projectionDeletionSigningProfiles,
  verifyRetainedRpcRetirementSelection,
  verifyUnproposedRetirementTrust,
} from './rpc-retirement-signing.ts';

test('runtime retirement recovery follows every immutable successor before any mutation', async () => {
  const ids = [1, 2, 3].map((n) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`);
  const expected = {
    body: { selection: { inputId: 'original' } },
    key: 'original-key',
    resourceRef: 'original-resource',
  };
  const entry = (successor) => ({
    kind: 'evidence-deletion-runtime',
    candidate: {
      candidate: expected.body,
      businessIdempotencyKey: expected.key,
      resourceRef: expected.resourceRef,
      operationRef: null,
      successorApprovalRef: successor ? `urn:openpc:resource:${successor}` : null,
    },
  });
  const entries = ids.map((_, i) => entry(ids[i + 1]));
  const read = async (id) => entries[ids.indexOf(id)];
  assert.deepEqual(await readRuntimeRetirementApprovalChain(read, ids[0], expected), {
    approvalId: ids[2],
    current: entries[2],
  });
  for (const change of [
    { businessIdempotencyKey: 'replacement-key' },
    { resourceRef: 'replacement-resource' },
    { candidate: { selection: { inputId: 'different' } } },
    { successorApprovalRef: `urn:openpc:resource:${ids[0]}` },
    { successorApprovalRef: 'urn:openpc:resource:invalid' },
    { operationRef: 'consumed-original' },
  ]) {
    const bad = async (id) =>
      id === ids[1]
        ? { ...entries[1], candidate: { ...entries[1].candidate, ...change } }
        : read(id);
    await assert.rejects(readRuntimeRetirementApprovalChain(bad, ids[0], expected));
  }
  entries[2].candidate.operationRef = 'consumed-original';
  const committed = await readRuntimeRetirementApprovalChain(read, ids[0], expected);
  assert.equal(committed.current.candidate.operationRef, 'consumed-original');
  assert.equal(committed.approvalId, ids[2]);
});

test('runtime retirement recovery refuses an existing observation before business mutation', async () => {
  const { mkdtemp, readFile, rm, symlink, writeFile } = await import('node:fs/promises');
  const { join } = await import('node:path');
  const root = await mkdtemp(
    join(process.env.OPENPC_TEST_TMP_ROOT ?? tmpdir(), 'retirement-observation-'),
  );
  try {
    const original = Buffer.from('{"status":404,"truthState":"DENIED"}');
    await writeFile(join(root, 'browser-execution.json'), original, { flag: 'wx' });
    await assert.rejects(
      requireNewRetirementObservation(root, 'browser-execution'),
      /public reconciliation before mutation/u,
    );
    assert.deepEqual(await readFile(join(root, 'browser-execution.json')), original);
    await symlink(join(root, 'absent'), join(root, 'dangling.json'));
    await assert.rejects(
      requireNewRetirementObservation(root, 'dangling'),
      /public reconciliation before mutation/u,
    );
    await requireNewRetirementObservation(root, 'browser-execution-fresh-attempt');
  } finally {
    await rm(root, { recursive: true });
  }
});

test('missing retirement trust rejects an affected proposal rather than repairing its denial', () => {
  assert.doesNotThrow(() => verifyUnproposedRetirementTrust([{ has_candidates: false }]));
  for (const rows of [
    [{ has_candidates: true }],
    [{ has_candidates: null }],
    [],
    [{ has_candidates: false }, { has_candidates: false }],
  ])
    assert.throws(() => verifyUnproposedRetirementTrust(rows));
});

test('projection setup leaves payload retirement versions with their separate signing owner', () => {
  const expected = {
    'hold': [
      ['pc.control.evidence-hold.create', 1],
      ['pc.control.evidence-hold.release', 1],
    ],
    'retention': [
      ['pc.control.retention-policy.activate', 1],
      ['pc.control.retention-policy.retire', 1],
    ],
    'deletion-local': [['pc.control.evidence-deletion.local', 1]],
    'deletion-projection': [
      ['pc.control.evidence-deletion.projection', 1],
      ['pc.control.evidence-deletion.projection', 2],
    ],
  };
  for (const [family, bindings] of Object.entries(expected)) {
    const profiles = projectionDeletionSigningProfiles(family);
    assert.deepEqual(
      profiles.map((p) => [p.profileId, p.profileVersion]),
      bindings,
    );
    for (const rpc of rpcRetirementSigningFamilies)
      assert.equal(
        profiles.some(
          (p) => p.profileId === rpc.profileId && p.profileVersion === rpc.profileVersion,
        ),
        false,
      );
  }
  for (const family of ['local-v2', 'projection-v3', '*', undefined])
    assert.throws(() => projectionDeletionSigningProfiles(family));
});

test('RPC retirement additions bind only the exact new canonical versions and pinned signing owner', () => {
  assert.deepEqual(
    rpcRetirementSigningFamilies.map(({ family }) => family),
    ['local-v2', 'batch-v2', 'projection-v3'],
  );
  for (const { family, profileVersion } of rpcRetirementSigningFamilies) {
    const profiles = rpcRetirementSigningProfiles(family);
    assert.equal(profiles.length, 1);
    const [profile] = profiles;
    assert.equal(profile.profileVersion, profileVersion);
    const descriptor = {
      participantId: '018f0000-0000-7000-8000-000000000101',
      privacyDomainId: '018f0000-0000-7000-8000-000000007201',
      workloadCredentialId: rpcRetirementSigningWorkload.credentialId,
      reference: `secret://local/control-rpc-retirement-018f0000-0000-7000-8000-000000007201-${family}-evidence#1`,
      version: '1',
      fingerprint: `sha256:${'01'.repeat(32)}`,
      publicKeySpkiHex: '02'.repeat(91),
      validFromNs: '1000',
      validUntilNs: '2000',
    };
    assert.equal(verifyRetainedRpcRetirementSelection(family, [], descriptor), false);
    const row = {
      profile_id: profile.profileId,
      profile_version: String(profileVersion),
      profile_digest: Buffer.from(profile.profileDigest.slice(7), 'hex'),
      state: 'ACTIVE',
      participant_id: descriptor.participantId,
      privacy_domain_id: descriptor.privacyDomainId,
      environment_id: 'local',
      workload_credential_id: descriptor.workloadCredentialId,
      signer_id: descriptor.fingerprint,
      public_key_spki_der: Buffer.from(descriptor.publicKeySpkiHex, 'hex'),
      secret_reference: descriptor.reference,
      secret_version: descriptor.version,
      valid_from_ns: descriptor.validFromNs,
      valid_until_ns: descriptor.validUntilNs,
    };
    assert.equal(verifyRetainedRpcRetirementSelection(family, [row], descriptor), true);
    for (const changed of [
      { ...row, profile_version: '1' },
      { ...row, profile_id: 'pc.control.evidence-deletion.raw-proof' },
      { ...row, state: 'REVOKED' },
      { ...row, state: 'RETIRED' },
      { ...row, profile_digest: Buffer.alloc(32) },
      { ...row, profile_digest: profile.profileDigest },
      { ...row, participant_id: 'foreign-participant' },
      { ...row, privacy_domain_id: 'foreign-privacy' },
      { ...row, environment_id: 'other' },
      { ...row, workload_credential_id: '018f0000-0000-7000-8000-000000000195' },
      { ...row, signer_id: `sha256:${'03'.repeat(32)}` },
      { ...row, public_key_spki_der: Buffer.alloc(91) },
      { ...row, secret_reference: 'secret://local/wrong-key#1' },
      { ...row, secret_version: '2' },
      { ...row, valid_from_ns: '0' },
      { ...row, valid_until_ns: '3000' },
    ])
      assert.throws(() => verifyRetainedRpcRetirementSelection(family, [changed], descriptor));
    assert.throws(() => verifyRetainedRpcRetirementSelection(family, [row, row], descriptor));
    for (const changed of [
      { ...descriptor, workloadCredentialId: '018f0000-0000-7000-8000-000000000195' },
      { ...descriptor, reference: 'secret://local/wrong-family#1' },
      { ...descriptor, version: '2' },
    ])
      assert.throws(() => verifyRetainedRpcRetirementSelection(family, [], changed));
  }
  for (const family of ['local-v1', 'projection-v2', 'raw-proof', '*', undefined])
    assert.throws(() => rpcRetirementSigningProfiles(family));
});

test('actual key preparation preserves its exact keys on retry and cannot overwrite another family', async () => {
  const { execFileSync } = await import('node:child_process');
  const { mkdtemp, mkdir, readFile, readdir, rm, writeFile } = await import('node:fs/promises');
  const { join } = await import('node:path');
  const parent = process.env.OPENPC_TEST_TMP_ROOT ?? tmpdir();
  const root = await mkdtemp(join(parent, 'rpc-signing-preparation-'));
  const secrets = join(root, 'secrets'),
    provider = join(root, 'provider');
  const privacy = '018f0000-0000-7000-8000-000000000201';
  try {
    await mkdir(secrets);
    const old = Buffer.from('retained family sentinel');
    const original = join(secrets, 'control_business_signing_public_key.der');
    await writeFile(original, old, { flag: 'wx' });
    const prepare = () =>
      execFileSync(
        process.execPath,
        [
          '--import',
          'tsx',
          'tests/integration/local-runtime/signing-provider-bootstrap.ts',
          secrets,
          provider,
          '--rpc-retirement',
          privacy,
        ],
        { stdio: 'pipe' },
      );
    prepare();
    const names = (await readdir(secrets))
      .filter((name) => name !== 'rpc-retirement-transport')
      .sort();
    assert.equal(names.length, 7);
    const before = await Promise.all(names.map((name) => readFile(join(secrets, name))));
    const fingerprints = new Set();
    const descriptors = [];
    for (const { family } of rpcRetirementSigningFamilies) {
      const name = `control_rpc_retirement_${privacy}_${family}_signing`;
      const descriptor = JSON.parse(
        await readFile(join(secrets, `${name}_descriptor.json`), 'utf8'),
      );
      assert.equal(descriptor.privacyDomainId, privacy);
      assert.equal(
        descriptor.reference,
        `secret://local/control-rpc-retirement-${privacy}-${family}-evidence#1`,
      );
      assert.equal(descriptor.state, 'ACTIVE');
      assert.equal(descriptor.workloadCredentialId, rpcRetirementSigningWorkload.credentialId);
      descriptors.push(descriptor);
      fingerprints.add(descriptor.fingerprint);
    }
    assert.equal(fingerprints.size, 3);
    prepare();
    assert.deepEqual(
      (await readdir(secrets)).filter((name) => name !== 'rpc-retirement-transport').sort(),
      names,
    );
    assert.deepEqual(await Promise.all(names.map((name) => readFile(join(secrets, name)))), before);
    assert.deepEqual(await readFile(original), old);
    const transport = join(secrets, 'rpc-retirement-transport');
    const transportNames = (await readdir(transport)).sort();
    const transportBefore = await Promise.all(
      transportNames.map((name) => readFile(join(transport, name))),
    );
    prepare();
    assert.deepEqual(
      await Promise.all(transportNames.map((name) => readFile(join(transport, name)))),
      transportBefore,
    );
    const { createFixtureSigningProvider } = await import('./signing-provider-fixture.ts');
    const { createHttpBusinessSigningProvider } =
      await import('../../../services/identity-service/src/domain/http-business-signing-provider.ts');
    const { businessSigningPurpose, validateBusinessProviderObservation } =
      await import('../../../services/identity-service/src/domain/business-signing-provider.ts');
    const { localOperationId } =
      await import('../../../services/identity-service/src/domain/local-operation-id.ts');
    const read = (name) => readFile(join(transport, name));
    const tls = await createFixtureSigningProvider({
      root: provider,
      initialKeys: [],
      certificate: await read('business_provider_server_cert.pem'),
      privateKey: await read('business_provider_server_key.pem'),
      ca: await read('business_provider_ca.pem'),
      clients: [
        {
          participantId: descriptors[0].participantId,
          privacyDomainId: privacy,
          environmentId: 'local',
          credentialId: rpcRetirementSigningWorkload.credentialId,
          workloadId: rpcRetirementSigningWorkload.workloadId,
          certificate: await read('business_api_cert.pem'),
          methods: ['INSPECT'],
          managedKeyOwners: [rpcRetirementSigningWorkload.credentialId],
          signingProfiles: [],
        },
      ],
    });
    let client;
    try {
      await new Promise((resolve) => tls.server.listen(0, '127.0.0.1', resolve));
      client = createHttpBusinessSigningProvider({
        origin: `https://127.0.0.1:${tls.server.address().port}`,
        trustCa: await read('business_provider_ca.pem'),
        certificate: await read('business_api_cert.pem'),
        privateKey: await read('business_api_key.pem'),
      });
      for (const descriptor of descriptors) {
        const request = {
          participantId: descriptor.participantId,
          privacyDomainId: privacy,
          environmentId: 'local',
          workloadCredentialId: rpcRetirementSigningWorkload.credentialId,
          callerWorkloadCredentialId: rpcRetirementSigningWorkload.credentialId,
          secretClass: 'SECRET-SIGNING-KEY',
          purpose: businessSigningPurpose,
          reference: descriptor.reference,
          version: descriptor.version,
          attemptId: localOperationId(),
          operationId: localOperationId(),
          method: 'INSPECT',
        };
        const observed = await client.perform(request);
        validateBusinessProviderObservation(request, observed);
        assert.deepEqual(observed.descriptor, descriptor);
        await assert.rejects(
          client.perform({
            ...request,
            attemptId: localOperationId(),
            callerWorkloadCredentialId: '018f0000-0000-7000-8000-000000000195',
          }),
        );
      }
    } finally {
      client?.close();
      await tls.close();
    }
    // Exercise the actual runtime entry point. Retirement has no baseline
    // envelope files or authority, and must still serve its pinned mTLS caller.
    const { spawn } = await import('node:child_process');
    const { once } = await import('node:events');
    const { request } = await import('node:https');
    const { stat } = await import('node:fs/promises');
    const aliases = join(root, 'runtime-secrets');
    await mkdir(aliases);
    for (const name of [
      'business_provider_ca',
      'business_provider_server_cert',
      'business_provider_server_key',
      'business_api_cert',
    ])
      await writeFile(join(aliases, name), await read(name + '.pem'), { mode: 0o600 });
    const child = spawn(
      process.execPath,
      ['--import', 'tsx', 'tests/integration/local-runtime/signing-provider-runtime.ts'],
      {
        env: {
          ...process.env,
          OPENPC_SIGNING_PROVIDER_SECRET_ROOT: aliases,
          OPENPC_SIGNING_PROVIDER_STATE_ROOT: provider,
          OPENPC_SIGNING_PROVIDER_RPC_RETIREMENT: '1',
          OPENPC_LOCAL_BOOTSTRAP_PRIVACY_DOMAIN_ID: privacy,
          OPENPC_LOCAL_SIGNING_PROVIDER_PORT: '0',
        },
        stdio: ['ignore', 'pipe', 'pipe'],
      },
    );
    let runtimeClient;
    try {
      const port = await new Promise((resolve, reject) => {
        const timeout = setTimeout(
          () => reject(new Error('Retirement runtime readiness timed out')),
          10000,
        );
        let output = '';
        child.stdout.on('data', (value) => {
          output += value;
          const match = /OPENPC_SIGNING_PROVIDER\|listening\|port=(\d+)/u.exec(output);
          if (match) {
            clearTimeout(timeout);
            resolve(Number(match[1]));
          }
        });
        child.once('error', (error) => {
          clearTimeout(timeout);
          reject(error);
        });
        child.once('exit', () => {
          clearTimeout(timeout);
          reject(new Error('Retirement runtime exited before readiness'));
        });
      });
      runtimeClient = createHttpBusinessSigningProvider({
        origin: `https://127.0.0.1:${port}`,
        trustCa: await read('business_provider_ca.pem'),
        certificate: await read('business_api_cert.pem'),
        privateKey: await read('business_api_key.pem'),
      });
      for (const descriptor of descriptors) {
        const observed = await runtimeClient.perform({
          participantId: descriptor.participantId,
          privacyDomainId: privacy,
          environmentId: 'local',
          workloadCredentialId: rpcRetirementSigningWorkload.credentialId,
          callerWorkloadCredentialId: rpcRetirementSigningWorkload.credentialId,
          secretClass: 'SECRET-SIGNING-KEY',
          purpose: businessSigningPurpose,
          reference: descriptor.reference,
          version: descriptor.version,
          attemptId: localOperationId(),
          operationId: localOperationId(),
          method: 'INSPECT',
        });
        assert.deepEqual(observed.descriptor, descriptor);
      }
      const tlsOptions = {
        ca: await read('business_provider_ca.pem'),
        cert: await read('business_api_cert.pem'),
        key: await read('business_api_key.pem'),
      };
      const denied = await new Promise((resolve, reject) => {
        const req = request(
          {
            hostname: '127.0.0.1',
            port,
            path: '/v1/identity-envelope-signing/perform',
            method: 'POST',
            ...tlsOptions,
            minVersion: 'TLSv1.3',
            maxVersion: 'TLSv1.3',
          },
          (response) => {
            response.resume();
            response.once('end', () => {
              clearTimeout(timeout);
              resolve(response.statusCode);
            });
          },
        );
        const timeout = setTimeout(() => req.destroy(new Error('Envelope probe timed out')), 5000);
        req.once('error', (error) => {
          clearTimeout(timeout);
          reject(error);
        });
        req.end('{}');
      });
      assert.equal(denied, 404);
      await assert.rejects(stat(join(provider, 'identity-envelope')), { code: 'ENOENT' });
    } finally {
      runtimeClient?.close();
      if (child.exitCode === null && child.signalCode === null) {
        const stopped = once(child, 'exit', { signal: AbortSignal.timeout(5000) });
        child.kill('SIGTERM');
        try {
          await stopped;
        } catch (error) {
          assert.equal(error.name, 'AbortError');
          if (child.exitCode === null && child.signalCode === null) {
            const killed = once(child, 'exit', { signal: AbortSignal.timeout(5000) });
            child.kill('SIGKILL');
            await killed;
          }
        }
      }
    }
    await writeFile(join(transport, 'unexpected'), 'partial transport marker');
    assert.throws(prepare);
    await rm(join(transport, 'unexpected'));
    assert.deepEqual(
      await Promise.all(transportNames.map((name) => readFile(join(transport, name)))),
      transportBefore,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('RPC payload continuation rejects malformed, duplicate or reordered original IDs before signing setup', async () => {
  const { rpcPayloadRetirementInputs, withRpcPayloadRetirementSigning } =
    await import('./evidence-rpc-payload-retirement-browser.mjs');
  const prefix = `rpc:${'a'.repeat(64)}:`;
  const ids = [17, 18, 19].map((n) => prefix + n);
  const retained = rpcPayloadRetirementInputs(ids);
  ids[0] = prefix + 16;
  assert.equal(retained[0], prefix + 17);
  for (const bad of [
    undefined,
    [],
    [prefix + 0],
    [prefix + '18446744073709551616'],
    [prefix + 17, prefix + 17],
    [prefix + 19, prefix + 18],
    ['foreign:record'],
    Array.from({ length: 17 }, (_, index) => prefix + (100 + index)),
  ]) {
    assert.throws(() => rpcPayloadRetirementInputs(bad));
    await assert.rejects(
      withRpcPayloadRetirementSigning({ recordIds: bad }, () =>
        assert.fail('Invalid originals cannot reach runtime allocation or mutation'),
      ),
    );
  }
});

test('runtime source trust prepares distinct exact-profile keys and preserves existing originals', async () => {
  const { runtimeSourceSigningFamilies, runtimeSourceSigningProfiles, runtimeSourceSigningName } =
    await import('./runtime-source-disposition-signing.ts');
  const { execFileSync } = await import('node:child_process');
  const { mkdtemp, mkdir, readFile, readdir, rm, writeFile } = await import('node:fs/promises');
  const { join } = await import('node:path');
  const root = await mkdtemp(
    join(process.env.OPENPC_TEST_TMP_ROOT ?? tmpdir(), 'runtime-source-signing-'),
  );
  const secrets = join(root, 'secrets'),
    provider = join(root, 'provider');
  const privacy = '018f0000-0000-7000-8000-000000007201';
  try {
    await mkdir(secrets);
    await writeFile(join(secrets, 'original.key'), 'preserved original');
    const prepare = () =>
      execFileSync(
        process.execPath,
        [
          '--import',
          'tsx',
          'tests/integration/local-runtime/signing-provider-bootstrap.ts',
          secrets,
          provider,
          '--runtime-source-disposition',
          privacy,
        ],
        { stdio: 'pipe' },
      );
    prepare();
    const names = (await readdir(secrets)).sort();
    const originals = await Promise.all(names.map((n) => readFile(join(secrets, n))));
    const keys = new Set();
    for (const { family } of runtimeSourceSigningFamilies) {
      const descriptor = JSON.parse(
        await readFile(
          join(secrets, runtimeSourceSigningName(privacy, family) + '_descriptor.json'),
        ),
      );
      assert.equal(descriptor.privacyDomainId, privacy);
      assert.equal(descriptor.state, 'ACTIVE');
      keys.add(descriptor.fingerprint);
      assert.ok(runtimeSourceSigningProfiles(family).every((p) => p.profileVersion === 1));
    }
    assert.equal(keys.size, 3);
    assert.deepEqual(
      runtimeSourceSigningProfiles('disposition').map((p) => p.catalogOperationId),
      ['CFG-OP-DISPOSE-RUNTIME-ARTIFACT-SOURCE'],
    );
    assert.deepEqual(
      runtimeSourceSigningProfiles('retirement').map((p) => p.catalogOperationId),
      ['CFG-OP-DELETE-RUNTIME-ARTIFACT-BATCH'],
    );
    assert.throws(() => runtimeSourceSigningProfiles('*'));
    assert.throws(() => runtimeSourceSigningName('wrong', 'retention'));
    prepare();
    assert.deepEqual(await Promise.all(names.map((n) => readFile(join(secrets, n)))), originals);
    assert.equal(names.length, 7);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
