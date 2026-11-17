import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { setTimeout as wait } from 'node:timers/promises';
import { pathToFileURL } from 'node:url';

// Deployment policy publication and administrative simulation do
// not establish a deployment intent, provider creation proof or send authority.
export async function simulateDeployment({ load, save, call, body, mode, policyB }) {
  const publication = await load('configuration-deployment-policy-resource.json');
  const wallet = await load('deployment-wallet.json');
  const request = {
    deploymentPolicyId: publication.deploymentPolicyId.split(':').at(-1),
    method: 'eth_sendRawTransaction',
    signedTransaction: wallet.signedTransaction,
  };
  const path = '/internal/v1/policy-simulations';
  const input = { ...body, request };
  const response = call(path, input);
  assert.equal(response.authorityLabel, 'SIMULATION_ONLY');
  assert.equal(response.evaluation.truthState, mode === 'reorg' ? 'STALE' : 'SUCCESS');
  assert.equal('inputBytes' in response.evaluation, false);
  assert.equal('resultBytes' in response.evaluation, false);
  const filename = policyB
    ? 'typed-deployment-b-simulation.json'
    : 'typed-deployment-simulation.json';
  if (mode === 'simulate' || mode === 'simulate-b') {
    await save(filename, response);
    assert.deepEqual(call(path, input), response, 'exact signed deployment simulation replays');
    for (const signedTransaction of [wallet.wrongChain, wallet.wrongInitCode]) {
      const denied = call(path, { ...input, request: { ...request, signedTransaction } });
      assert.equal(denied.evaluation.truthState, 'DENIED');
    }
    for (const injected of [{ ready: true }, { approval: 'APPROVED' }, { evaluatedAtMs: 1 }])
      call(path, { ...input, request: { ...request, ...injected } }, 422);
    call(path, input, 403, { privacyDomainId: '018f0000-0000-7000-8000-000000000202' });
    call(path, input, 403, { participantId: '018f0000-0000-7000-8000-000000000102' });
  } else if (mode === 'restart' || mode === 'restart-b') {
    assert.deepEqual(response, await load(filename));
  }
  process.stdout.write(
    `OPENPC_DEPLOYMENT_SIMULATION_${mode.toUpperCase()}|PASS|authority=SIMULATION_ONLY\n`,
  );
}

// Public approval/preparation must already exist. Exercise the actual reservation
// owner with overlapping transactions, then leave its sole RESERVED claim for
// the ordinary worker to authenticate, hand off and send. No HANDOFF is seeded.
export async function concurrentNativeReservations(
  secretRoot,
  participantId,
  privacyDomainId,
  firstOperation,
  secondOperation,
) {
  const { Pool } = await import('pg');
  const { deploymentReservationCore } =
    await import('../../../services/control-api/src/configuration/deployment/intent-core.ts');
  const { reserveDeploymentAddress, DeploymentReservationError } =
    await import('../../../services/control-api/src/configuration/deployment/reservations.ts');
  const commandIds = [firstOperation, secondOperation].map((value) => {
    assert.match(value, /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u);
    return value;
  });
  assert.notEqual(commandIds[0], commandIds[1]);
  const pool = new Pool({
    host: '127.0.0.1',
    port: 55432,
    database: 'openpc_control',
    user: 'openpc_local_control_worker',
    password: (
      await readFile(join(secretRoot, 'control_worker_runtime_db_password.txt'), 'utf8')
    ).trim(),
    max: 3,
    statement_timeout: 10_000,
  });
  const clients = [];
  let pending;
  try {
    for (let index = 0; index < 3; index++) clients.push(await pool.connect());
    const [first, second, observer] = clients;
    for (const [index, client] of clients.entries()) {
      await client.query('begin');
      await client.query(
        `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,
          'ACT-DEPLOYMENT_SUBMISSIONS_CREATE_RESOURCE-V1',true)`,
        [participantId, privacyDomainId, commandIds[index % 2]],
      );
      await client.query(
        "select pg_advisory_xact_lock_shared(hashtextextended('module-admission:'||$1||':'||$2,0))",
        [participantId, privacyDomainId],
      );
    }
    const claims = [];
    for (const commandId of commandIds) {
      const source = await observer.query(
        `select c.resource_id::text attempt_id,c.candidate_document,
          i.preparation_bytes,i.publication_bytes
        from control.mutation_candidate c join control.deployment_intent i
          on i.participant_id=c.participant_id and i.privacy_domain_id=c.privacy_domain_id
          and 'urn:openpc:resource:'||i.deployment_intent_id::text=c.candidate_document->>'deploymentIntentId'
        where c.consumed_operation_id=$1 and c.state='CONSUMED'
          and c.catalog_operation_id='CFG-OP-SUBMIT-DEPLOYMENT'
          and c.participant_id=$2 and c.privacy_domain_id=$3
          and i.module_generation_digest=openpc.deployment_module_generation(i.participant_id,i.privacy_domain_id)`,
        [commandId, participantId, privacyDomainId],
      );
      assert.equal(source.rowCount, 1, 'concurrent claims require real public approved commands');
      const row = source.rows[0];
      const preparation = JSON.parse(row.preparation_bytes.toString('utf8'));
      const binding = deploymentReservationCore({
        recordBytes: `0x${row.preparation_bytes.toString('hex')}`,
        publication: JSON.parse(row.publication_bytes.toString('utf8')),
        signedTransaction: row.candidate_document.signedTransaction,
        commandId,
        attemptId: row.attempt_id,
        nowMs: Date.now(),
      });
      assert.ok(binding.nativeValueAuthorizationId);
      assert.ok(BigInt(preparation.intent.valueWei) > 0n);
      claims.push({ binding, nonce: preparation.intent.nonce });
    }
    assert.equal(
      claims[0].binding.nativeValueAuthorizationId,
      claims[1].binding.nativeValueAuthorizationId,
    );
    assert.equal(
      claims[0].binding.nativeValueAuthorizationDigest,
      claims[1].binding.nativeValueAuthorizationDigest,
    );
    assert.notEqual(claims[0].nonce, claims[1].nonce);
    assert.notEqual(claims[0].binding.contractAddress, claims[1].binding.contractAddress);
    assert.notEqual(claims[0].binding.transactionHash, claims[1].binding.transactionHash);
    assert.equal(
      (await reserveDeploymentAddress(first, claims[0].binding, claims[0].nonce)).state,
      'RESERVED',
    );
    let settled = false;
    pending = reserveDeploymentAddress(second, claims[1].binding, claims[1].nonce).then(
      (value) => ({ value }),
      (error) => ({ error }),
    );
    void pending.then(() => {
      settled = true;
    });
    const until = Date.now() + 5000;
    let blocked = false;
    while (!settled && Date.now() < until) {
      blocked = (
        await observer.query('select $1::int=any(pg_blocking_pids($2)) blocked', [
          first.processID,
          second.processID,
        ])
      ).rows[0].blocked;
      if (blocked) break;
      await wait(10);
    }
    assert.equal(blocked, true, 'second positive claim must physically wait for the first');
    assert.equal(settled, false);
    await first.query('commit');
    const outcome = await pending;
    assert.ok(outcome.error instanceof DeploymentReservationError);
    assert.equal(outcome.error.code, 'UNAVAILABLE');
    await second.query('rollback');
    const retained = await observer.query(
      `select command_id::text,state from control.deployment_address_reservation
       where native_value_authorization_id=$1`,
      [claims[0].binding.nativeValueAuthorizationId],
    );
    assert.deepEqual(retained.rows, [{ command_id: commandIds[0], state: 'RESERVED' }]);
    process.stdout.write(
      'OPENPC_NATIVE_CONCURRENCY|PASS|real-approved-commands|physical-sql-wait|one-reservation|no-handoff\n',
    );
  } finally {
    // Release the winner before waiting for a blocked contender during failure.
    for (const client of clients) await client.query('rollback');
    if (pending) await pending;
    for (const client of clients) client.release();
    await pool.end();
  }
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href &&
  process.argv[2] === 'native-concurrency'
) {
  await concurrentNativeReservations(...process.argv.slice(3));
} else if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [walletPath, abiArtifactId, actionIntentDigest, factoryBindingId] = process.argv.slice(2);
  assert.ok(walletPath && abiArtifactId && actionIntentDigest);
  const wallet = JSON.parse(await readFile(walletPath, 'utf8'));
  const zero = `0x${'00'.repeat(32)}`;
  const fee = (value, fallback) =>
    `0x${BigInt(value ?? fallback)
      .toString(16)
      .padStart(64, '0')}`;
  process.stdout.write(
    JSON.stringify({
      actionIntentId: 'ACT-DEPLOYMENT_POLICIES_CREATE_RESOURCE-V1',
      actionIntentDigest,
      reason: 'Publish the exact deployment definition for governed simulation and release.',
      definition: {
        schemaVersion: '1.0.0',
        profileId:
          wallet.mechanism === 'TRANSACTION_CREATE'
            ? 'reference:direct'
            : `reference:${wallet.mechanism}`,
        profileVersion: '1.0.0',
        assuranceLevel: 'A0',
        creationEvidence:
          wallet.mechanism === 'CREATE3'
            ? 'COMPLETE_SOLADY_CREATE3_CALL_AND_OPCODE_V1'
            : 'COMPLETE_SINGLE_CREATION_CALL_AND_OPCODE_V1',
        chainId: wallet.chainId ?? '31337',
        networkId: wallet.networkId ?? 'openpc-local',
        genesisDigest: wallet.genesisDigest ?? `sha256:${'11'.repeat(32)}`,
        abiArtifactId,
        artifact: {
          mode: 'EXACT_INIT_CODE',
          initCode: wallet.initCode,
          runtimeCodeHash: wallet.runtimeCodeHash,
        },
        route: factoryBindingId
          ? {
              mechanism: wallet.mechanism,
              runtimeBindingId: factoryBindingId,
              canonicalSignature: wallet.canonicalSignature,
              codeHash: wallet.factoryCodeHash,
              adapterDigest: `sha256:${'42'.repeat(32)}`,
              ...(wallet.mechanism === 'CREATE3'
                ? { helperProfile: 'SOLADY_CREATE3_V0_1_26' }
                : {}),
              ...(['CREATE2', 'CREATE3'].includes(wallet.mechanism)
                ? {
                    arguments: wallet.arguments ?? 'INIT_CODE_SALT',
                    saltNamespaceDigest: `sha256:${'43'.repeat(32)}`,
                    saltTransform: 'IDENTITY',
                  }
                : {}),
            }
          : { mechanism: 'TRANSACTION_CREATE' },
        allowedSenders: [wallet.sender],
        requiredRoles: ['urn:openpc:role:018f0000-0000-7000-8000-000000000801'],
        approvalRequirement: 'NONE',
        webauthnRequired: false,
        expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
        transactionPolicy: {
          version: 1,
          allowedTransactionTypes: [0, 1, 2],
          maximumValue:
            wallet.mechanism === 'TRANSACTION_CREATE' &&
            process.env.OPENPC_LOCAL_RUNTIME_DEPLOYMENT_ONLY === '1'
              ? fee('10', 0)
              : zero,
          maximumGasLimit: wallet.gasLimit ?? '1000000',
          maximumFeePerGas: fee(wallet.maximumFeePerGas, 255),
          maximumPriorityFeePerGas: fee(wallet.priorityFeePerGas, 10),
          maximumRawTransactionBytes: 131072,
          maximumCalldataBytes: 32768,
          maximumAccessListAddresses: 128,
          maximumAccessListStorageKeys: 1024,
        },
      },
    }),
  );
}
