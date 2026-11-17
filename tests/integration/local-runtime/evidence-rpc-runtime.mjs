import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';
import { connectRpcEnospcFixture } from './rpc-journal-crash-fixture.mjs';
const execute = promisify(execFile);
const exec = async (command, args) => {
  try {
    return await execute(command, args, { timeout: 30000, maxBuffer: 4 * 1024 * 1024 });
  } catch (error) {
    const diagnostic =
      typeof error.stderr === 'string' &&
      /^OPENPC_RPC_ENOSPC_FIXTURE\|FAIL\|phase=(input|claim|inspect|fill|drain)\|cause=(MULTIPLE_FAILURES|ENOSPC|EACCES|EPERM|ENOENT|EEXIST|ELOOP|EROFS|CONTRACT)$/u.test(
        error.stderr.trim(),
      )
        ? ` (${error.stderr.trim()})`
        : '';
    throw new Error(`RPC evidence fixture command failed: ${command}${diagnostic}`);
  }
};

export function assertPublicRpcDenial(response, id) {
  assert.equal(response.status, 403);
  assert.equal(response.body.id, id);
  assert.equal(response.body.error?.code, -32001);
  assert.equal(response.body.error?.data?.pcCode, 'PC-RUNTIME-3001');
  assert.equal(response.body.error?.data?.truthState, 'DENIED');
  assert.equal(response.body.error?.data?.retryable, false);
  assert.equal(response.body.result, undefined);
}

export function assertRpcStorageFailure(response, id) {
  // Physical ENOSPC is an atomic journal I/O failure. The separate logical
  // evidence-capacity boundary owns PC-RUNTIME-3010/503.
  assert.equal(response.status, 500, JSON.stringify(response.body));
  assert.equal(response.body.id, id);
  assert.equal(response.body.error?.data?.pcCode, 'PC-DATA-6005');
  assert.equal(response.body.error?.data?.truthState, 'FAILED');
  assert.equal(response.body.error?.data?.retryable, false);
  assert.equal(response.body.result, undefined);
}

export async function exerciseRpcEvidence(
  secretRoot,
  targetRuntimeId,
  compose,
  {
    privacyDomainId,
    clientCertificateFile = join(secretRoot, 'identity_mtls_rotated_cert.pem'),
    clientKeyFile = join(secretRoot, 'identity_mtls_rotated_key.pem'),
    providerRequestsFile = join(secretRoot, '..', 'data/rpc-provider/requests.jsonl'),
    contractAddress = `0x${'11'.repeat(20)}`,
    terminalCases = false,
    terminalOnly = false,
    retainedDenialId,
    physicalEnospc,
  },
) {
  assert.ok(privacyDomainId, 'RPC acceptance requires its actual privacy context');
  assert.match(contractAddress, /^0x[0-9a-f]{40}$/u);
  const target = (
    await exec(compose[0], [
      ...compose.slice(1),
      '--profile',
      'astra05',
      'ps',
      '-q',
      'runtime-target',
    ])
  ).stdout.trim();
  const journal = `/runtime/evidence/${targetRuntimeId}`;
  assert.ok(
    !physicalEnospc || !terminalOnly,
    'Physical capacity requires its complete recovery path',
  );
  const diskFault = physicalEnospc
    ? await connectRpcEnospcFixture(physicalEnospc, {
        targetContainerId: target,
        targetRuntimeId,
        execute: exec,
      })
    : undefined;
  const tls = [
    '--silent',
    '--show-error',
    '--max-time',
    '20',
    '--tlsv1.3',
    '--tls-max',
    '1.3',
    '--cacert',
    join(secretRoot, 'identity_mtls_ca.pem'),
    '--cert',
    clientCertificateFile,
    '--key',
    clientKeyFile,
    '-H',
    'Content-Type: application/json',
  ];
  const identity = async () => {
    const response = JSON.parse(
      (
        await exec('curl', [
          ...tls,
          '--data',
          JSON.stringify({
            runtimeContext: {
              privacyDomainId,
              targetRuntimeId,
            },
          }),
          'https://127.0.0.1:53443/internal/v1/workload/authenticate',
        ])
      ).stdout,
    );
    assert.ok(response.runtime?.assertionCoseSign1, 'fresh mTLS authority required');
    return Buffer.from(response.runtime.assertionCoseSign1, 'base64').toString('hex');
  };
  const request = async (method, params, id) => {
    const result = (
      await exec('curl', [
        ...tls,
        '--resolve',
        'localhost:18545:127.0.0.1',
        '-H',
        `x-openpc-identity-assertion: ${await identity()}`,
        '--data',
        JSON.stringify({ jsonrpc: '2.0', id, method, params }),
        '--write-out',
        '\n%{http_code}',
        'https://localhost:18545/rpc',
      ])
    ).stdout;
    const lines = result.trim().split('\n');
    const status = Number(lines.pop());
    return { status, body: JSON.parse(lines.join('\n')) };
  };
  const sourceBytes = async () =>
    (await exec('docker', ['exec', target, 'cat', `${journal}/sealed-decisions.json`])).stdout;
  const source = async () => JSON.parse(await sourceBytes());
  const sourceDigest = async () =>
    createHash('sha256')
      .update(await sourceBytes())
      .digest('hex');
  const keyFingerprint = async () => {
    const digest = (
      await exec('docker', [
        'exec',
        target,
        'sha256sum',
        '/run/secrets/runtime_target_evidence_encryption_key',
      ])
    ).stdout.split(' ')[0];
    assert.match(digest, /^[0-9a-f]{64}$/u);
    return digest;
  };
  const snapshot = async () =>
    JSON.parse(
      (
        await exec('docker', [
          'exec',
          target,
          '/usr/local/bin/openpc-control-worker',
          'runtime-evidence-snapshot',
          'rpc',
        ])
      ).stdout,
    );
  const providerCount = async () =>
    (await readFile(providerRequestsFile, 'utf8')).trim().split('\n').length;
  const allowedParams = [
    { to: contractAddress, data: `0x70a08231${'0'.repeat(24)}${'1'.repeat(40)}` },
    '0xa',
  ];
  const terminals = async () => {
    // The inactive, local-only barrier must already be loaded before fresh
    // authority is acquired. No fault is added to a product image or journal.
    const maps = (await exec('docker', ['exec', target, 'cat', '/proc/1/maps'])).stdout;
    assert.ok(maps.includes('/runtime/rpc-journal-crash-fixture.so'));
    const environment = (await exec('docker', ['inspect', '-f', '{{json .Config.Env}}', target]))
      .stdout;
    assert.ok(JSON.parse(environment).includes(`OPENPC_RPC_JOURNAL_FAULT_DIRECTORY=${journal}`));
    await exec('docker', [
      'exec',
      target,
      'sh',
      '-c',
      'test ! -e "$1/acceptance-pause.arm" && test ! -e "$1/acceptance-pause.reached"',
      'sh',
      journal,
    ]);
    const before = await snapshot(),
      chain = await source(),
      sent = await providerCount();
    assert.ok(Object.values(before.records).every((record) => record.status !== 'Reserved'));
    const deniedParams = structuredClone(allowedParams);
    deniedParams[0].data = `0x70a08231${'0'.repeat(24)}${'2'.repeat(40)}`;
    let afterDenial, deniedChain, denialId, denial;
    if (retainedDenialId) {
      assert.ok(terminalOnly, 'A retained denial belongs only to explicit continuation');
      afterDenial = before;
      deniedChain = chain;
      denialId = retainedDenialId;
      denial = before.records[denialId];
      assert.ok(denial, 'Authenticate the exact retained decision without resubmission');
      // The protected adapter forwards the original body bytes unchanged. Its
      // controlled external provider records SHA-256 of every received body.
      const digest = createHash('sha256')
        .update(
          JSON.stringify({ jsonrpc: '2.0', id: 7121, method: 'eth_call', params: deniedParams }),
        )
        .digest('hex');
      const observed = (await readFile(providerRequestsFile, 'utf8'))
        .trim()
        .split('\n')
        .map((line) => JSON.parse(line));
      assert.equal(
        observed.some((row) => row.digest === digest),
        false,
        'Retained denial never reached the provider',
      );
      assert.equal(chain.records.filter((row) => row.receipt.record_id === denialId).length, 2);
    } else {
      const denied = await request('eth_call', deniedParams, 7121);
      assertPublicRpcDenial(denied, 7121);
      assert.equal(await providerCount(), sent, 'A committed typed-argument denial cannot send');
      afterDenial = await snapshot();
      deniedChain = await source();
      const added = Object.entries(afterDenial.records).filter(([id]) => !(id in before.records));
      assert.equal(added.length, 1, 'Exactly one owned request reaches the decision journal');
      [denialId, denial] = added[0];
      assert.equal(denied.body.error.data.traceId, denial.trace_id);
      assert.deepEqual(deniedChain.records.slice(0, chain.records.length), chain.records);
      assert.equal(
        deniedChain.records.length,
        chain.records.length + 2,
        'Real reservation and committed denial',
      );
      assert.ok(deniedChain.records.slice(-2).every((r) => r.receipt.record_id === denialId));
    }
    assert.equal(denial.status.Committed?.effect, 'DENY_TERMINAL');
    assert.equal(denial.status.Committed?.pc_code, 'PC-RUNTIME-3003');
    assert.ok(denial.trace_id);
    process.stdout.write(
      `OPENPC_RPC_TERMINAL|PASS|COMMITTED-DENY_TERMINAL|${retainedDenialId ? 'authenticated-retained-decision' : 'real-typed-argument-denial'}|no-provider-send\n`,
    );

    // One owned, authenticated request is in flight. Pause after its actual
    // reservation has reached fsync, authenticate that exact state, and kill
    // the writer. Signals cannot resume the blocked fsync caller.
    await exec('docker', [
      'exec',
      target,
      'sh',
      '-c',
      'set -C; umask 077; printf "pause-after-fsync:1\\n" > "$1/acceptance-pause.arm"',
      'sh',
      journal,
    ]);
    const pending = request('eth_call', allowedParams, 7122).then(
      (response) => ({ response }),
      () => ({ transportFailed: true }),
    );
    let killed = false;
    try {
      let reached = false;
      for (let attempt = 0; attempt < 100 && !reached; attempt++) {
        const state = (
          await exec('docker', [
            'exec',
            target,
            'sh',
            '-c',
            'if test -f "$1/acceptance-pause.reached"; then cat "$1/acceptance-pause.reached"; fi',
            'sh',
            journal,
          ])
        ).stdout;
        reached = state === 'pause-after-fsync:1\n';
        if (!reached) await delay(25);
      }
      assert.equal(reached, true, 'Owned request must reach its live durable reservation');
      assert.equal(
        (await exec('docker', ['inspect', '-f', '{{.State.Running}}', target])).stdout.trim(),
        'true',
      );
      const stopped = await snapshot(),
        stoppedChain = await source();
      const pendingRecords = Object.entries(stopped.records).filter(
        ([id]) => !(id in afterDenial.records),
      );
      assert.equal(pendingRecords.length, 1);
      const [interruptedId, reserved] = pendingRecords[0];
      assert.equal(reserved.status, 'Reserved');
      assert.ok(reserved.trace_id && reserved.trace_id !== denial.trace_id);
      assert.ok(
        reserved.valid_until_ns > Date.now() * 1e6,
        'Observe the interruption while original authority is live',
      );
      if (!retainedDenialId) assert.deepEqual(reserved.capsule_digest, denial.capsule_digest);
      assert.deepEqual(
        stoppedChain.records.slice(0, deniedChain.records.length),
        deniedChain.records,
      );
      assert.equal(stoppedChain.records.length, deniedChain.records.length + 1);
      assert.equal(stoppedChain.records.at(-1).receipt.record_id, interruptedId);
      assert.equal(await providerCount(), sent, 'Paused reservation has no provider effect');
      await exec('docker', ['kill', '--signal', 'KILL', target]);
      killed = true;
      const outcome = await pending;
      assert.notEqual(outcome.response?.status, 200);
      assert.equal(outcome.response?.body?.result, undefined);
      await exec('docker', ['start', target]);
      let recovered;
      for (let attempt = 0; attempt < 100; attempt++) {
        recovered = await snapshot();
        if (recovered.records[interruptedId]?.status === 'Interrupted') break;
        await delay(25);
      }
      assert.deepEqual(recovered.records[interruptedId], { ...reserved, status: 'Interrupted' });
      const finalChain = await source();
      assert.deepEqual(
        finalChain.records.slice(0, stoppedChain.records.length),
        stoppedChain.records,
      );
      assert.equal(finalChain.records.length, stoppedChain.records.length + 1);
      assert.equal(finalChain.records.at(-1).receipt.record_id, interruptedId);
      assert.equal(await providerCount(), sent, 'Restart must not replay an interrupted request');
      await exec('docker', ['exec', target, 'rm', `${journal}/acceptance-pause.reached`]);
      process.stdout.write(
        'OPENPC_RPC_TERMINAL|PASS|RESERVED-INTERRUPTED|live-durable-barrier|exact-identity-recovery|no-resubmit-no-send\n',
      );
      return {
        denialId,
        interruptedId,
        denialSequences: deniedChain.records
          .filter((row) => row.receipt.record_id === denialId)
          .map((row) => row.receipt.sequence),
        lastSequence: finalChain.records.length,
      };
    } finally {
      // On a failed assertion the caller retains the original journal and
      // failure. Never resume a possibly paused writer or replay its request.
      if (!killed) await exec('docker', ['kill', '--signal', 'KILL', target]);
      await pending;
    }
  };
  if (terminalOnly) return terminals();
  const prior = await source();
  const sends = await providerCount();
  const denied = await request('openpc_invalid_evidence_probe', [], 7101);
  assert.notEqual(denied.status, 200);
  assert.equal(denied.body.result, undefined);
  assert.equal(await providerCount(), sends, 'denial cannot contact provider');
  const afterDeny = await source();
  assert.ok(
    afterDeny.records.length > prior.records.length,
    'denial must durably extend encrypted evidence',
  );
  // Reserve a deterministic lexicographic selection boundary for the later
  // terminal-family retirement, using actual denials rather than seeded rows.
  if (terminalCases) {
    for (let id = 7130; (await source()).records.length < 10 && id < 7140; id++) {
      const rejected = await request('openpc_invalid_evidence_probe', [], id);
      assert.notEqual(rejected.status, 200);
      assert.equal(rejected.body.result, undefined);
      assert.equal(await providerCount(), sends);
    }
  }
  const beforeFailure = await snapshot();
  const beforeStorageFailure = await source();
  const originalDigest = diskFault ? await sourceDigest() : undefined;
  const originalKey = diskFault ? await keyFingerprint() : undefined;
  let storageFailure;
  let stagingDirectoryCreated = false;
  try {
    if (diskFault) await diskFault.begin();
    else {
      await exec('docker', ['exec', target, 'mkdir', `${journal}/sealed-decisions.next`]);
      stagingDirectoryCreated = true;
    }
    const failed = await request('eth_call', allowedParams, 7102);
    assertRpcStorageFailure(failed, 7102);
    if (diskFault) {
      await diskFault.observed();
      assert.equal(
        await sourceDigest(),
        originalDigest,
        'Physical failure preserves exact committed ciphertext',
      );
      assert.equal(await keyFingerprint(), originalKey);
    }
    assert.equal(
      await providerCount(),
      sends,
      'failed durable reservation must precede provider I/O',
    );
    assert.deepEqual(
      (await source()).records,
      beforeStorageFailure.records,
      'failed storage cannot advance sequence',
    );
  } catch (error) {
    storageFailure = error;
  }
  try {
    if (diskFault) await diskFault.drain();
    else if (stagingDirectoryCreated)
      await exec('docker', ['exec', target, 'rmdir', `${journal}/sealed-decisions.next`]);
  } catch (cleanupError) {
    storageFailure = storageFailure
      ? new AggregateError(
          [storageFailure, cleanupError],
          'Storage failure and owned fixture cleanup both failed',
        )
      : cleanupError;
  }
  if (storageFailure) throw storageFailure;
  assert.deepEqual((await snapshot()).records, beforeFailure.records);
  if (diskFault) {
    // Draining ballast grants no new admission: the existing poisoned owner
    // must still refuse this fresh read without advancing or contacting RPC.
    assertRpcStorageFailure(await request('eth_call', allowedParams, 7141), 7141);
    assert.equal(await providerCount(), sends);
    assert.equal(await sourceDigest(), originalDigest);
    assert.equal(await keyFingerprint(), originalKey);
    await diskFault.observed();
  }
  // A failed journal write poisons the live owner until recovery. Exercise an
  // abrupt bounded restart rather than spending the default ten-second stop
  // grace inside the Fact's original thirty-second lifetime.
  await exec(compose[0], [...compose.slice(1), 'restart', '--timeout', '1', 'runtime-target']);
  await exec(compose[0], [
    ...compose.slice(1),
    '--profile',
    'astra05',
    'up',
    '-d',
    '--wait',
    '--no-deps',
    '--no-build',
    '--pull',
    'never',
    'runtime-target',
  ]);
  if (diskFault) {
    await diskFault.restarted();
    assert.equal(await sourceDigest(), originalDigest);
    assert.equal(await keyFingerprint(), originalKey);
  }
  assert.deepEqual((await snapshot()).records, beforeFailure.records);
  const recovered = await request('eth_call', allowedParams, 7103);
  assert.equal(recovered.status, 200, JSON.stringify(recovered.body));
  assert.equal(recovered.body.result, `0x${'00'.repeat(30)}1234`);
  assert.ok((await source()).records.length > afterDeny.records.length);
  assert.equal(await providerCount(), sends + 1);
  if (diskFault) {
    const recoveredChain = await source();
    assert.deepEqual(recoveredChain.binding, beforeStorageFailure.binding);
    assert.deepEqual(
      recoveredChain.records.slice(0, beforeStorageFailure.records.length),
      beforeStorageFailure.records,
    );
    for (const [index, record] of recoveredChain.records.entries())
      assert.equal(
        record.receipt.sequence,
        index + 1,
        'Recovery cannot reuse or skip an admitted sequence',
      );
    assert.equal(await keyFingerprint(), originalKey);
  }
  if (terminalCases) await terminals();
  // Cross both the eight-record export page and decimal sequence boundaries
  // through real denied requests, so cursor ordering is exercised in CI.
  for (let id = 7104; (await source()).records.length < 17 && id < 7120; id++) {
    const denied = await request('openpc_invalid_evidence_probe', [], id);
    assert.notEqual(denied.status, 200);
    assert.equal(denied.body.result, undefined);
    assert.equal(await providerCount(), sends + 1);
  }
  assert.ok((await source()).records.length >= 17);
  process.stdout.write('OPENPC_RPC_ADMISSION|live-effects-passed|after-bounded-restart\n');
  process.stdout.write(
    'OPENPC_RPC_ADMISSION|PASS|real-allow-deny|pre-provider-storage-failure|no-release-no-send|unchanged-sequence|restart-recovery\n',
  );
  if (diskFault)
    process.stdout.write(
      'OPENPC_RPC_PHYSICAL_ENOSPC|PASS|kernel-write-ENOSPC|partial-staging|original-ciphertext-key-sequence|no-send|poisoned-until-restart|same-filesystem-recovery\n',
    );
}
