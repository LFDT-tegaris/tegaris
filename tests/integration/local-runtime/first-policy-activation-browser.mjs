import { readInitialActivationDisposition } from './target-disposition-readback.mjs';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { expect } from '@playwright/test';
import { command, loadReferences } from './policy-release-browser-commands.mjs';
import {
  renewFirstPolicyTarget,
  refreshFirstPolicyAuthority,
} from './first-policy-target-renewal.mjs';

const execute = promisify(execFile);

/** Historical readback is selected only after the original public occurrence is
 * already matched. A caller flag cannot complete or renew a pending activation. */
export function activationContinuationMode(
  occurrence,
  { historicalReadbackOnly, completedRpc, historical },
) {
  assert.ok(
    ['REQUESTED', 'STAGING', 'ACTIVATING', 'PARTIAL', 'ACTIVE_MATCHED'].includes(occurrence.state),
  );
  if (historicalReadbackOnly || completedRpc) {
    assert.equal(occurrence.state, 'ACTIVE_MATCHED');
    assert.equal(occurrence.matchedTargetCount, '1');
    assert.equal(occurrence.totalTargetCount, '1');
    return 'READBACK';
  }
  // An expired observation cannot turn an unfinished original into an active
  // target. Refresh the real workload observation and reconcile that original;
  // the ACTIVATE branch submits only an occurrence still in REQUESTED state.
  return historical && occurrence.state === 'ACTIVE_MATCHED' ? 'RENEW' : 'ACTIVATE';
}

/** An original occurrence remains historical proof after a later governed
 * version becomes active. Keep each digest bound to its own authoritative row. */
export function assertActivationPolicyReadback(
  occurrence,
  parent,
  { policySetId, semanticDigest, historicalReadbackOnly },
) {
  assert.equal(occurrence.targetGenerationDigest, semanticDigest);
  assert.equal(parent.policySetId, policySetId);
  assert.equal(parent.state, 'ACTIVE');
  assert.match(parent.activeVersionDigest, /^sha256:[0-9a-f]{64}$/u);
  if (!historicalReadbackOnly) assert.equal(parent.activeVersionDigest, semanticDigest);
  assert.ok(BigInt(parent.revision) > 1n);
}

export async function activateFirstPolicy({
  maker,
  checker,
  input,
  authored,
  checkpoint,
  publicRead,
  persist,
  evidenceRoot,
  secretRoot,
  journey = 'first-policy',
  onActivated,
  historicalReadbackOnly = false,
}) {
  const discovery = JSON.parse(
    await readFile(join(evidenceRoot, 'discovery-credential-input.json'), 'utf8'),
  );
  const compose = JSON.parse(process.env.OPENPC_POLICY_SET_COMPOSE_JSON ?? 'null');
  assert.ok(Array.isArray(compose) && compose[0] === 'docker' && compose[1] === 'compose');
  const ownerRoot = join(evidenceRoot, '../..');
  const tls = join(ownerRoot, 'data/runtime-bootstrap/runtime/tls');
  const priorIdentity = JSON.parse(
    await readFile(join(evidenceRoot, `${journey}-workload-identity.json`), 'utf8').catch(
      (error) => {
        if (error.code !== 'ENOENT') throw error;
        return 'null';
      },
    ),
  );
  const refresh = () =>
    refreshFirstPolicyAuthority({
      secretRoot,
      evidenceRoot,
      privacyDomainId: input.privacyDomainId,
      targetId: discovery.targetId,
      journey,
    });
  const observe = async () => {
    await execute(
      compose[0],
      [
        ...compose.slice(1),
        '--profile',
        'astra05',
        'up',
        '-d',
        '--no-deps',
        '--no-build',
        '--pull',
        'never',
        'runtime-target',
      ],
      { timeout: 20000 },
    );
    await expect
      .poll(
        async () => {
          if (!historicalReadbackOnly) {
            let stdout;
            try {
              ({ stdout } = await execute(
                'curl',
                [
                  '--silent',
                  '--show-error',
                  '--max-time',
                  '2',
                  '--tlsv1.3',
                  '--tls-max',
                  '1.3',
                  '--cacert',
                  join(secretRoot, 'identity_mtls_ca.pem'),
                  '--cert',
                  join(tls, 'ads-client.pem'),
                  '--key',
                  join(tls, 'ads-client.key'),
                  '-H',
                  'Content-Type: application/json',
                  '--data',
                  JSON.stringify({
                    jsonrpc: '2.0',
                    id: 0,
                    method: 'openpc_invalid_observation_probe',
                    params: [],
                  }),
                  '--write-out',
                  '\n%{http_code}',
                  'https://localhost:18545/rpc',
                ],
                { timeout: 3000 },
              ));
            } catch {
              return false;
            }
            const lines = stdout.trim().split('\n');
            const status = Number(lines.pop());
            let body;
            try {
              body = JSON.parse(lines.join('\n'));
            } catch {
              return false;
            }
            assert.notEqual(
              status,
              200,
              'the observation probe never authorizes a business request',
            );
            assert.equal(body.result, undefined);
          }
          try {
            await execute(
              compose[0],
              [
                ...compose.slice(1),
                '--profile',
                'astra05',
                'exec',
                '-T',
                'runtime-target',
                '/usr/local/bin/openpc-control-worker',
                'runtime-target-ready',
              ],
              { timeout: 3000 },
            );
          } catch {
            return false;
          }
          return true;
        },
        { timeout: 25000, intervals: [250, 500, 1000] },
      )
      .toBe(true);
  };
  const refs = checkpoint.references;
  if (historicalReadbackOnly) assert.ok(refs.occurrenceId, 'Original activation required');
  if (!refs.occurrenceId) {
    const target = await publicRead(
      `/api/v1/runtime-targets/urn:openpc:resource:${discovery.targetId}`,
    );
    assert.equal(target.state, input.predecessorDigest ? 'ACTIVE_MATCHED' : 'DISCOVERED');
    if (input.predecessorDigest) assert.ok(target.activeGenerationDigest);
    else assert.equal(target.activeGenerationDigest, null);
    checkpoint.targetBeforeActivation = target;
    await refresh();
    await maker.getByRole('button', { name: 'Refresh policy workflow', exact: true }).click();
    await maker.getByText('PUBLISHED', { exact: true }).waitFor();
    const operation = await command(maker, 'Stage target activation', 'CREATE_OCCURRENCE');
    refs.occurrenceId = operation.resourceRef.split(':').at(-1);
    checkpoint.occurrenceOperation = operation;
    await persist();
  }
  await loadReferences(checker, refs);
  let occurrence = await publicRead(
    `/api/v1/activation-occurrences/urn:openpc:resource:${refs.occurrenceId}`,
  );
  assert.ok(
    ['REQUESTED', 'STAGING', 'ACTIVATING', 'PARTIAL', 'ACTIVE_MATCHED'].includes(occurrence.state),
  );
  const historical =
    checkpoint.originalActivationHistoricalOnly ||
    (occurrence.state !== 'REQUESTED' &&
      priorIdentity?.runtime?.expiresAtNs &&
      BigInt(priorIdentity.runtime.expiresAtNs) <= BigInt(Date.now()) * 1000000n);
  const completedRpc =
    /^rpc-policy(?:-[2-9][0-9]*)?$/u.test(journey) && checkpoint.rpcCustodyPassed === true;
  const continuation = activationContinuationMode(occurrence, {
    historicalReadbackOnly,
    completedRpc,
    historical,
  });
  if (continuation === 'READBACK') {
    // Original public outcome only; no new Fact, activation or RPC effect.
    // Custody/retention acceptance remains independent of this browser tail.
  } else if (continuation === 'RENEW') {
    await renewFirstPolicyTarget({
      input,
      targetId: discovery.targetId,
      checkpoint,
      publicRead,
      persist,
      connect: async () => {
        await execute(
          compose[0],
          [
            ...compose.slice(1),
            '--profile',
            'astra05',
            'up',
            '-d',
            '--no-deps',
            '--no-build',
            '--pull',
            'never',
            'runtime-envoy',
          ],
          { timeout: 20000 },
        );
      },
      refresh,
      observe,
      secretRoot,
      evidenceRoot,
      priorAuthorityExpiresAtNs: priorIdentity?.runtime?.expiresAtNs,
      failedRenewalSuccessorOf: process.env.OPENPC_FIRST_POLICY_RENEWAL_SUCCESSOR_OF,
    });
  } else {
    await refresh();
    await execute(
      compose[0],
      [
        ...compose.slice(1),
        '--profile',
        'astra05',
        'up',
        '-d',
        '--no-deps',
        '--no-build',
        '--pull',
        'never',
        'runtime-target',
      ],
      { timeout: 20000 },
    );
    if (occurrence.state === 'REQUESTED') {
      let intercepted;
      await checker.route('**/api/v1/ui/policy-release-workbench', async (route) => {
        if (
          route.request().method() === 'POST' &&
          route.request().postDataJSON()?.command === 'ACTIVATE'
        ) {
          const response = await route.fetch();
          intercepted = { status: response.status(), operation: await response.json() };
          checkpoint.activationResponse = intercepted;
          await persist();
          await route.abort('connectionreset');
        } else await route.continue();
      });
      await checker
        .getByRole('button', { name: 'Activate with security key', exact: true })
        .click();
      await checker
        .getByText(
          'The activation response was lost. Checking the original operation before continuing.',
          {
            exact: true,
          },
        )
        .waitFor();
      await checker.unroute('**/api/v1/ui/policy-release-workbench');
      assert.equal(intercepted?.status, 202, JSON.stringify(intercepted));
    }
    await observe();
  }
  await loadReferences(checker, refs);
  await expect(checker.getByText('ACTIVE MATCHED', { exact: true })).toBeVisible({
    timeout: 45000,
  });
  occurrence = await publicRead(
    `/api/v1/activation-occurrences/urn:openpc:resource:${refs.occurrenceId}`,
  );
  assert.equal(occurrence.state, 'ACTIVE_MATCHED');
  assert.equal(occurrence.matchedTargetCount, '1');
  assert.equal(occurrence.totalTargetCount, '1');
  const parent = await publicRead(`/api/v1/policy-sets/${authored.policySetId}`);
  assertActivationPolicyReadback(occurrence, parent, {
    policySetId: authored.policySetId,
    semanticDigest: input.semanticDigest,
    historicalReadbackOnly,
  });
  let originalDisposition;
  const inspectDisposition = async () => {
    if (journey !== 'first-policy' || historicalReadbackOnly || continuation === 'READBACK') return;
    originalDisposition = await readInitialActivationDisposition({
      secretRoot,
      participantId: input.participantId,
      privacyDomainId: input.privacyDomainId,
      targetId: discovery.targetId,
      prior: originalDisposition,
      renewalOperationId:
        continuation === 'RENEW' ? checkpoint.targetRenewal.operation.operationId : undefined,
    });
  };
  await inspectDisposition();
  // A dependent runtime journey consumes the original live authority before
  // restart/readback and visual inspection spend its bounded lifetime.
  if (onActivated && continuation !== 'READBACK')
    await onActivated({ discovery, compose, ownerRoot });
  // Historical public state is owned by Policy/Control. The current target may
  // serve a later source-only generation whose readiness requires a NEW signed
  // observation. Do not invent that authority or append RPC effects to read history.
  if (historicalReadbackOnly) {
    await execute(
      compose[0],
      [...compose.slice(1), 'restart', 'policy-service', 'control-worker'],
      { timeout: 40000 },
    );
    await execute(
      compose[0],
      [
        ...compose.slice(1),
        '--profile',
        'astra05',
        'up',
        '-d',
        '--wait',
        '--no-recreate',
        '--no-deps',
        '--no-build',
        '--pull',
        'never',
        'policy-service',
        'control-worker',
      ],
      { timeout: 45000 },
    );
  } else {
    await execute(
      compose[0],
      [
        ...compose.slice(1),
        '--profile',
        'astra05',
        'up',
        '-d',
        '--wait',
        '--no-recreate',
        '--no-deps',
        '--no-build',
        '--pull',
        'never',
        'runtime-target',
      ],
      { timeout: 45000 },
    );
    await execute(
      compose[0],
      [...compose.slice(1), 'restart', 'policy-service', 'control-worker', 'runtime-target'],
      { timeout: 40000 },
    );
    await observe();
    await inspectDisposition();
    await execute(
      compose[0],
      [
        ...compose.slice(1),
        '--profile',
        'astra05',
        'up',
        '-d',
        '--wait',
        '--no-recreate',
        '--no-deps',
        '--no-build',
        '--pull',
        'never',
        'policy-service',
        'control-worker',
        'runtime-target',
      ],
      { timeout: 45000 },
    );
  }
  assert.deepEqual(
    await publicRead(`/api/v1/activation-occurrences/urn:openpc:resource:${refs.occurrenceId}`),
    occurrence,
  );
  assert.deepEqual(await publicRead(`/api/v1/policy-sets/${authored.policySetId}`), parent);
  await checker.reload();
  await checker.getByText('ACTIVE MATCHED', { exact: true }).waitFor();
  checkpoint.activeOccurrence = occurrence;
  checkpoint.activePolicySet = parent;
  await persist();
  await writeFile(
    join(evidenceRoot, `${journey}-activation-result.json`),
    JSON.stringify({ occurrence, parent }),
    { mode: 0o600 },
  );
  process.stdout.write(
    `OPENPC_POLICY_ACTIVATION|PASS|${journey}|${historicalReadbackOnly ? 'approved-original-release' : 'real-mTLS|approved-release|lost-response'}|${historicalReadbackOnly ? 'original-activation-historical-readback-only' : completedRpc ? 'completed-rpc-historical-readback' : historical ? 'original-historical-and-public-renewal' : input.predecessorDigest ? 'successor-generation' : 'first-generation'}|one-target-matched|active-parent-revision|${historicalReadbackOnly ? 'policy-worker-restart-readback|target-readiness-independent' : 'worker-target-restart-readback'}\n`,
  );
}
