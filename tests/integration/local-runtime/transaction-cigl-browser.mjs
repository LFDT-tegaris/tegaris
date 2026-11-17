import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { expect } from '@playwright/test';
import {
  governThroughWorkbench,
  readWorkbenchApproval,
  withTransactionBrowser,
} from './transaction-workbench-browser.mjs';

await promisify(execFile)(
  'bash',
  ['scripts/maintenance/run-bounded.sh', '--profile', 'runtime-target', '--reuse', '--', 'true'],
  { maxBuffer: 1024 * 1024 },
);
const [mode, secretRoot, evidenceRoot, ...args] = process.argv.slice(2);
assert.ok(
  ['settings', 'grants', 'journey', 'retained', 'renewal', 'restart-readback'].includes(mode) &&
    secretRoot &&
    evidenceRoot,
);
const load = async (name) => JSON.parse(await readFile(join(evidenceRoot, name), 'utf8'));
const endpoint = '/api/v1/ui/transaction-workbench';

async function readResource(page, kind, resourceRef) {
  await page.getByRole('button', { name: 'New request', exact: true }).click();
  await page.getByLabel('Request type', { exact: true }).selectOption(kind);
  await page.getByLabel('Resource ID', { exact: true }).fill(resourceRef.slice(-36));
  const pending = page.waitForResponse(
    (response) =>
      response.request().method() === 'GET' &&
      new URL(response.url()).pathname === endpoint &&
      new URL(response.url()).searchParams.get('resourceId') === resourceRef.slice(-36),
  );
  await page.getByRole('button', { name: 'Read resource', exact: true }).click();
  const response = await pending;
  assert.equal(response.status(), 200);
  return (await response.json()).result;
}

await withTransactionBrowser(
  {
    secretRoot,
    evidenceRoot,
    artifacts: join(evidenceRoot, 'transaction-browser', `cigl-${mode}`),
    route: '/operate/rpc-transactions',
  },
  async ({ maker, checker, actors }) => {
    const govern = (input) =>
      governThroughWorkbench({ maker, checker, checkerId: actors.checker.principalId, ...input });
    if (mode === 'settings') {
      const { definition } = JSON.parse(args[0]);
      const settings = await govern({
        label: 'Publish interaction settings',
        fields: { 'Interaction settings definition': JSON.stringify(definition) },
        reason:
          'Publish bounded, fail-closed interaction analysis through independent browser review.',
      });
      assert.deepEqual(settings.completed.result.definition, definition);
      assert.equal(settings.completed.operation.state, 'SUCCEEDED');
      await writeFile(
        join(evidenceRoot, 'cigl-settings-resource.json'),
        JSON.stringify(settings.completed.result),
        { mode: 0o600 },
      );
      process.stdout.write(
        'OPENPC_CIGL_BROWSER_SETTINGS|PASS|independent-review|webauthn|public-readback\n',
      );
      return;
    }

    const [dataRoot, targetRef, composeJson] = args;
    assert.ok(dataRoot && targetRef && composeJson);
    const compose = JSON.parse(composeJson);
    assert.deepEqual(compose.slice(0, 2), ['docker', 'compose']);
    const [wallet, nextWallet, method, nestedMethod] = await Promise.all([
      load('cigl-wallet.json'),
      load('cigl-renewed-wallet.json'),
      load('configuration-contract-method-resource.json'),
      load('configuration-contract-read-b-resource.json'),
    ]);
    const workloadId = 'urn:openpc:workload:018f0000-0000-7000-8000-000000000191';
    // Match the independently accepted workload client: each observation uses
    // a fresh verified mTLS connection across Envoy's listener replacement.
    const post = async (url, body, headers = {}) => {
      const invocation = promisify(execFile)(
        'curl',
        [
          '--silent',
          '--show-error',
          '--max-time',
          '8',
          '--tlsv1.3',
          '--tls-max',
          '1.3',
          '--cacert',
          join(secretRoot, 'identity_mtls_ca.pem'),
          '--cert',
          join(secretRoot, 'identity_mtls_rotated_cert.pem'),
          '--key',
          join(secretRoot, 'identity_mtls_rotated_key.pem'),
          '--header',
          'Content-Type: application/json',
          ...Object.entries(headers).flatMap(([name, value]) => ['--header', `${name}: ${value}`]),
          '--data-binary',
          '@-',
          '--write-out',
          '\n%{http_code}',
          url,
        ],
        { encoding: 'buffer', timeout: 10_000, maxBuffer: 2 * 1024 * 1024 },
      );
      invocation.child.stdin.end(JSON.stringify(body));
      let stdout;
      try {
        ({ stdout } = await invocation);
      } catch (error) {
        // execFile errors include arguments; never expose the assertion header.
        const code =
          error.code === 28
            ? 'ETIMEDOUT'
            : error.code === 7
              ? 'ECONNREFUSED'
              : [52, 56].includes(error.code)
                ? 'ECONNRESET'
                : 'WORKLOAD_TRANSPORT';
        const path = new URL(url).pathname;
        process.stdout.write(`OPENPC_CIGL_WORKLOAD_TRANSPORT|path=${path}|code=${code}\n`);
        throw Object.assign(new Error(`Workload transport failed at ${path}`), { code });
      }
      const separator = stdout.lastIndexOf(10);
      const status = Number(stdout.subarray(separator + 1).toString('ascii'));
      assert.ok(separator >= 0 && Number.isInteger(status) && status >= 100 && status <= 599);
      return { status, bytes: stdout.subarray(0, separator) };
    };
    let identity;
    const refreshIdentity = async () => {
      const response = await post('https://127.0.0.1:53443/internal/v1/workload/authenticate', {
        runtimeContext: {
          privacyDomainId: '018f0000-0000-7000-8000-000000000201',
          targetRuntimeId: targetRef.slice(-36),
        },
      });
      assert.equal(response.status, 200);
      identity = JSON.parse(response.bytes);
      assert.equal(identity.workloadId, workloadId);
      return Number(BigInt(identity.runtime.expiresAtNs) / 1_000_000n) - Date.now();
    };
    const targetRequest = async (path, body, refresh = true) => {
      if (refresh) await refreshIdentity();
      assert.ok(
        identity && BigInt(identity.runtime.expiresAtNs) > BigInt(Date.now()) * 1_000_000n,
        'workload observation requires unexpired signed identity',
      );
      return post(`https://localhost:18545${path}`, body, {
        'x-openpc-identity-assertion': Buffer.from(
          identity.runtime.assertionCoseSign1,
          'base64',
        ).toString('hex'),
      });
    };
    const sends = async () =>
      (
        await readFile(join(dataRoot, 'rpc-provider/cigl-submissions.jsonl'), 'utf8').catch(
          (error) => {
            if (error.code === 'ENOENT') return '';
            throw error;
          },
        )
      )
        .trim()
        .split('\n')
        .filter(Boolean)
        .map(JSON.parse);
    const raw = (value) => ({
      jsonrpc: '2.0',
      id: 3,
      method: 'eth_sendRawTransaction',
      params: [value.signedTransaction],
    });
    if (mode === 'restart-readback') {
      const grant = await readWorkbenchApproval(maker, args[3]);
      assert.equal(grant.result.status, 'DISABLED');
      assert.equal((await sends()).length, 1);
      assert.equal((await targetRequest('/rpc', raw(nextWallet))).status, 403);
      assert.equal((await sends()).length, 1);
      const original = await readWorkbenchApproval(maker, args[4]);
      assert.equal(original.operation.state, 'SUCCEEDED');
      await maker.screenshot({
        path: join(evidenceRoot, 'cigl-renewed-target-readback.png'),
        fullPage: true,
      });
      process.stdout.write(
        'OPENPC_CIGL_RESTART_DENIAL|PASS|disabled-grant|fresh-authentication|fresh-nonce-denied|one-send|original-operation-preserved\n',
      );
      return;
    }
    const createActiveGrant = async () => {
      const grant = await govern({
        label: 'Create method grant',
        fields: {
          'Runtime binding reference': nestedMethod.runtimeBindingId,
          'Method selector': nestedMethod.selector,
          'Recipient type': 'WORKLOAD',
          'Workload reference': workloadId,
          'Interface': 'RAW_SUBMISSION',
          'Decision': 'ALLOW',
          'Expected runtime binding revision': '1',
          'Expected method revision': nestedMethod.revision,
        },
        reason: 'Create a disabled grant for the exact nested method and workload.',
      });
      assert.equal(grant.completed.result.status, 'DISABLED');
      const grantRef = grant.completed.candidate.resourceRef;
      return govern({
        label: 'Change method grant status',
        fields: {
          'Resource reference': grantRef,
          'Expected revision': grant.completed.result.revision,
          'Grant status': 'ACTIVE',
        },
        reason: 'Activate the independently reviewed nested-method grant.',
      });
    };
    if (mode === 'grants') {
      const activeGrant = await createActiveGrant();
      assert.equal(activeGrant.completed.result.status, 'ACTIVE');
      await writeFile(
        join(evidenceRoot, 'cigl-browser-grant.json'),
        JSON.stringify({ approvalId: activeGrant.approvalId }),
        { mode: 0o600 },
      );
      process.stdout.write(
        'OPENPC_CIGL_BROWSER_GRANT|PASS|independent-review|webauthn|active-readback\n',
      );
      return;
    }
    const activateCompiled = async (compiledProfile, before, analysisPath, policyRenewal) => {
      const { currentSources: source, result, ...profile } = compiledProfile;
      assert.equal(result.methodCount, 2);
      assert.equal(result.grantCount, 1);
      const fields = {
        'Resource reference': source.targetRuntimeId,
        'Expected revision': source.targetRevision,
        'Expected generation digest': source.installedCapsuleDigest,
        'Participant epoch': source.participantEpoch,
        ...(policyRenewal === undefined
          ? {}
          : { 'Approved policy renewal (optional)': JSON.stringify(policyRenewal) }),
        'Compiled profile selections': JSON.stringify([
          {
            profileId: profile.profileId,
            profileRevision: profile.revision,
            profileDigest: result.profileDigest,
            compilationArtifactDigest: result.artifactDigest,
            grantSourcesDigest: source.grantSourcesDigest,
          },
        ]),
      };
      if (policyRenewal !== undefined) {
        const denialCandidates = [
          {
            ...policyRenewal,
            expectedRevision: String(BigInt(policyRenewal.expectedRevision) + 1n),
          },
          { ...policyRenewal, policyGenerationDigest: `sha256:${'ab'.repeat(32)}` },
        ];
        for (const changed of denialCandidates) {
          await govern({
            label: 'Activate compiled profiles',
            fields: { ...fields, 'Approved policy renewal (optional)': JSON.stringify(changed) },
            reason:
              'Reject a renewal whose approved occurrence revision or source generation does not match.',
            expectedExecutionStatus: 412,
          });
          assert.equal((await sends()).length, 0);
          assert.deepEqual(
            await readResource(maker, 'cigl-activation', source.targetRuntimeId),
            before,
          );
        }
        process.stdout.write(
          'OPENPC_CIGL_RENEWAL_DENIALS|PASS|stale-occurrence|wrong-policy|unchanged-target|zero-sends\n',
        );
      }
      await expect
        .poll(refreshIdentity, { timeout: 60_000, intervals: [500, 1000] })
        .toBeGreaterThan(45_000);
      const activated = await govern({
        label: 'Activate compiled profiles',
        fields,
        reason: 'Activate the exact compiled profile and read back its real runtime effect.',
        loseExecutionResponse: true,
      });
      let installed;
      await expect
        .poll(
          async () => {
            try {
              // Activation fences source authority while waiting for this request
              // observation. Use the already authenticated, still-valid assertion;
              // re-authenticating here waits on that fence before sending the probe.
              await targetRequest(
                analysisPath,
                { signedTransaction: wallet.signedTransaction },
                false,
              );
            } catch (error) {
              // The signed activation handoff briefly withdraws the old serving
              // process. Retry only this read-only observation, never activation.
              if (!['ETIMEDOUT', 'ECONNRESET', 'ECONNREFUSED', 'EPIPE'].includes(error.code))
                throw error;
              process.stdout.write(
                `OPENPC_CIGL_BROWSER_TRANSIENT|activation-observation|${error.code}\n`,
              );
            }
            installed = await readWorkbenchApproval(maker, activated.approvalId);
            return installed.operation?.state;
          },
          { timeout: 30_000, intervals: [250, 500] },
        )
        .toBe('SUCCEEDED');
      assert.equal(installed.result.state, 'ACTIVE_MATCHED');
      assert.equal(
        installed.result.activeGenerationDigest,
        installed.result.desiredGenerationDigest,
      );
      assert.notEqual(installed.result.activeGenerationDigest, before.activeGenerationDigest);
      await writeFile(
        join(evidenceRoot, 'cigl-browser-activation.json'),
        JSON.stringify({ operationId: installed.operation.operationId }),
        { mode: 0o600 },
      );
      return installed;
    };
    let grantRef, activeGrant, analysisPath;
    if (mode === 'retained' || mode === 'renewal') {
      const [grantApprovalId, activationApprovalId, reviewApprovalId] = args.slice(3);
      for (const id of [grantApprovalId, activationApprovalId, reviewApprovalId])
        assert.match(id, /^[0-9a-f-]{36}$/u);
      activeGrant = { completed: await readWorkbenchApproval(maker, grantApprovalId) };
      grantRef = activeGrant.completed.candidate.resourceRef;
      assert.equal(activeGrant.completed.result.status, 'ACTIVE');
      assert.equal(
        activeGrant.completed.result.definition.runtimeBindingId,
        nestedMethod.runtimeBindingId,
      );
      assert.equal(activeGrant.completed.result.definition.subject.id, workloadId);
      const installed = await readWorkbenchApproval(maker, activationApprovalId);
      assert.equal(installed.operation.state, 'SUCCEEDED');
      assert.equal(installed.result.state, 'ACTIVE_MATCHED');
      assert.equal(
        installed.result.activeGenerationDigest,
        installed.result.desiredGenerationDigest,
      );
      const reviewed = await readWorkbenchApproval(maker, reviewApprovalId);
      assert.equal(reviewed.result.review.profileCompilation, 'COMPILED');
      assert.equal(
        reviewed.result.review.profile.currentSources.installedCapsuleDigest,
        installed.result.activeGenerationDigest,
      );
      assert.equal(reviewed.result.review.profile.currentSources.targetRuntimeId, targetRef);
      analysisPath = `/api/v1/cigl-analyses/${reviewed.result.analysisId}/observe`;
      if (mode === 'renewal') {
        const renewal = await load('cigl-policy-renewal.json');
        await activateCompiled(
          reviewed.result.review.profile,
          installed.result,
          analysisPath,
          renewal,
        );
        const original = await readWorkbenchApproval(maker, activationApprovalId);
        assert.equal(original.operation.state, 'SUCCEEDED');
        assert.equal(original.operation.operationId, installed.operation.operationId);
        process.stdout.write(
          'OPENPC_CIGL_PROFILED_RENEWAL|PASS|public-policy-authority|independent-profile-review|fresh-webauthn|installed-lineage|original-operation-preserved\n',
        );
      }
      assert.equal((await sends()).length, 0);
      await refreshIdentity();
      process.stdout.write(
        'OPENPC_CIGL_BROWSER_RETAINED_ACTIVATION|PASS|original-completed-operation|exact-profile-lineage|fresh-identity|zero-sends\n',
      );
    } else {
      assert.equal((await targetRequest('/rpc', raw(wallet))).status, 403);
      assert.equal((await sends()).length, 0);
      const before = await readResource(maker, 'cigl-activation', targetRef);
      assert.equal(before.state, 'ACTIVE_MATCHED');
      const analysis = await govern({
        label: 'Create interaction analysis',
        fields: {
          'Runtime target reference': targetRef,
          'Installed generation digest': before.activeGenerationDigest,
          'Runtime binding reference': method.runtimeBindingId,
          'Method policy reference': method.contractMethodPolicyId,
          'Runtime binding revision': '1',
          'Method policy revision': method.revision,
          'Workload reference': workloadId,
          'Transaction hash': wallet.transactionHash,
          'Analysis lifetime (seconds)': '300',
        },
        reason: 'Analyze the exact workload transaction without granting execution authority.',
      });
      const analysisRef = analysis.completed.result.analysisId;
      assert.equal(analysis.completed.result.runtimePermission, 'NONE');
      analysisPath = `/api/v1/cigl-analyses/${analysisRef}/observe`;
      const observation = await targetRequest(analysisPath, {
        signedTransaction: wallet.signedTransaction,
      });
      assert.equal(observation.status, 200);
      const observed = await govern({
        label: 'Record signed observation',
        fields: {
          'Resource reference': analysisRef,
          'Expected revision': analysis.completed.result.revision,
          'Signed analysis receipt': `0x${observation.bytes.toString('hex')}`,
        },
        reason: 'Record the target-signed receipt for this exact interaction analysis.',
      });
      const observedResult = observed.completed.result;
      assert.equal(observedResult.state, 'OBSERVED');
      assert.equal(observedResult.observation.unresolvedCount, 0);
      assert.equal(observedResult.observation.actions.length, 1);
      assert.equal(observedResult.runtimePermission, 'NONE');
      if (args[3]) {
        assert.match(args[3], /^[0-9a-f-]{36}$/u);
        activeGrant = { completed: await readWorkbenchApproval(maker, args[3]) };
        grantRef = activeGrant.completed.candidate.resourceRef;
        assert.equal(activeGrant.completed.result.status, 'ACTIVE');
        assert.equal(
          activeGrant.completed.result.definition.runtimeBindingId,
          nestedMethod.runtimeBindingId,
        );
        assert.equal(activeGrant.completed.result.definition.subject.id, workloadId);
        process.stdout.write('OPENPC_CIGL_BROWSER_RETAINED_GRANT|PASS|public-current-readback\n');
      } else {
        activeGrant = await createActiveGrant();
        grantRef = activeGrant.completed.candidate.resourceRef;
      }
      const reviewed = await govern({
        label: 'Review interaction actions',
        fields: {
          'Resource reference': analysisRef,
          'Expected revision': observedResult.revision,
          'Action review definition': JSON.stringify({
            analysisDigest: observedResult.observation.analysisDigest,
            actions: observedResult.observation.actions.map(({ actionDigest }) => ({
              actionDigest,
              maximumValue: Array(32).fill(0),
            })),
            program: null,
          }),
        },
        reason: 'Compile only the exact observed action with zero native value.',
      });
      let compiled;
      await expect
        .poll(
          async () => {
            compiled = await readWorkbenchApproval(maker, reviewed.approvalId);
            return compiled.result?.review?.profileCompilation;
          },
          { timeout: 30_000, intervals: [250, 500] },
        )
        .toBe('COMPILED');
      assert.equal(compiled.result.runtimePermission, 'NONE');
      assert.equal(compiled.operation.state, 'SUCCEEDED');
      assert.equal((await sends()).length, 0);
      await activateCompiled(compiled.result.review.profile, before, analysisPath);
    }
    const { stdout: activationBytes } = await promisify(execFile)(
      compose[0],
      [
        ...compose.slice(1),
        'exec',
        '-T',
        'runtime-target',
        'cat',
        `/runtime/agent/${targetRef.slice(-36)}/activation.json`,
      ],
      { encoding: 'buffer', timeout: 10_000, maxBuffer: 4 * 1024 * 1024 },
    );
    const lifetime = promisify(execFile)(
      'cargo',
      [
        'run',
        '--quiet',
        '--locked',
        '--offline',
        '-p',
        'openpc-multi-rpc',
        '--example',
        'deployment_simulation_fixture',
        '--',
        '--lifetime',
      ],
      { timeout: 20_000, maxBuffer: 1024 * 1024 },
    );
    lifetime.child.stdin.end(activationBytes);
    const expiryNs = BigInt((await lifetime).stdout.trim());
    assert.ok(
      expiryNs > BigInt(Date.now()) * 1_000_000n,
      'completed activation recovery preserves original signed expiry; fresh identity cannot renew capsule authority',
    );
    const submission = await targetRequest('/rpc', raw(wallet));
    assert.equal(submission.status, 200);
    const receipt = JSON.parse(submission.bytes);
    assert.ok(receipt.result.operationId);
    assert.notEqual(receipt.result.truthState, 'SUCCESS');
    assert.equal((await sends()).length, 1);
    await writeFile(
      join(dataRoot, 'rpc-provider/cigl-renewed-wallet.json'),
      JSON.stringify(nextWallet),
      { mode: 0o600 },
    );
    assert.equal(
      (await targetRequest(analysisPath, { signedTransaction: nextWallet.signedTransaction }))
        .status,
      200,
    );
    const disabled = await govern({
      label: 'Change method grant status',
      fields: {
        'Resource reference': grantRef,
        'Expected revision': activeGrant.completed.result.revision,
        'Grant status': 'DISABLED',
      },
      reason:
        'Disable the source grant and deny a fresh transaction without a second provider send.',
    });
    await expect
      .poll(
        async () =>
          (await targetRequest(analysisPath, { signedTransaction: nextWallet.signedTransaction }))
            .status,
        { timeout: 10_000, intervals: [100, 250] },
      )
      .toBe(403);
    assert.equal((await targetRequest('/rpc', raw(nextWallet))).status, 403);
    assert.ok(
      expiryNs > BigInt(Date.now()) * 1_000_000n,
      'revocation must deny before signed runtime authority expires',
    );
    const replay = await targetRequest('/rpc', raw(wallet));
    assert.equal(replay.status, 200);
    assert.deepEqual(JSON.parse(replay.bytes), receipt);
    await promisify(execFile)(
      compose[0],
      [
        ...compose.slice(1),
        'restart',
        '--no-deps',
        'control-api',
        'policy-service',
        'control-worker',
        'runtime-envoy',
        'runtime-target',
      ],
      { timeout: 90_000, maxBuffer: 1024 * 1024 },
    );
    await expect
      .poll(
        async () => {
          try {
            return (
              await maker.request.get(
                `http://localhost:8080${endpoint}?approvalId=${disabled.approvalId}`,
              )
            ).status();
          } catch {
            return 0;
          }
        },
        { timeout: 30_000, intervals: [250, 500] },
      )
      .toBe(200);
    await maker.reload();
    const restarted = await readWorkbenchApproval(maker, disabled.approvalId);
    assert.equal(restarted.result.status, 'DISABLED');
    assert.equal(restarted.candidate.operationRef, disabled.completed.candidate.operationRef);
    assert.equal((await sends()).length, 1);
    const restartedReplay = await targetRequest('/rpc', raw(wallet));
    assert.equal(restartedReplay.status, 200);
    assert.deepEqual(JSON.parse(restartedReplay.bytes), receipt);
    assert.equal((await targetRequest('/rpc', raw(nextWallet))).status, 403);
    assert.equal((await sends()).length, 1);
    process.stdout.write(
      'OPENPC_CIGL_BROWSER|PASS|independent-review|signed-observation|grant-lifecycle|compiled-profile|activation-readback|response-loss|one-send|revocation|restart\n',
    );
  },
);
