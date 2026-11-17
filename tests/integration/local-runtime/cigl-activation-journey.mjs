import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

const [mode, root, ...args] = process.argv.slice(2);
const load = async (name) => JSON.parse(await readFile(join(root, name), 'utf8'));
const output = (value) => process.stdout.write(JSON.stringify(value));
const action = (id, digest, fields) => ({
  actionIntentId: id,
  actionIntentDigest: digest,
  reason: 'Accept the governed CIGL target lifecycle.',
  ...fields,
});
if (mode === 'binding') {
  output({
    ...JSON.parse(args[0]),
    transactionPolicy: {
      version: 1,
      allowedTransactionTypes: [2],
      maximumValue: `0x${'00'.repeat(32)}`,
      maximumGasLimit: '100000',
      maximumFeePerGas: `0x${'00'.repeat(31)}02`,
      maximumPriorityFeePerGas: `0x${'00'.repeat(31)}01`,
      maximumRawTransactionBytes: 4096,
      maximumCalldataBytes: 1024,
      maximumAccessListAddresses: 0,
      maximumAccessListStorageKeys: 0,
    },
  });
} else if (mode === 'settings') {
  output(
    action('ACT-CIGL_SETTINGS_CREATE_RESOURCE-V1', args[0], {
      definition: {
        schemaVersion: '1.0',
        scope: { kind: 'ALL_CHAINS' },
        mode: 'HYBRID_STRICT',
        enforcement: {
          ethCall: false,
          ethEstimateGas: false,
          prepareWrite: true,
          rawSubmission: true,
          deploymentConstructors: true,
          runtimeTraceForWrites: true,
          reviewedSchemaSubset: true,
          failClosed: true,
          rejectExternalStateOverrides: true,
        },
        traceLimits: { maxDepth: 16, maxFrames: 32, maxResponseBytes: 100000, timeoutMs: 5000 },
        traceProvider: 'DEBUG_TRACE_CALL',
        readinessScope: 'METHOD',
        schemaFallbackEnabled: false,
        precompileAllowlist: [],
        systemContractAllowlist: [],
        postMine: { enabled: true, freezeOnDivergence: false },
      },
    }),
  );
} else if (mode === 'analysis') {
  const target = await load('cigl-base-target.json'),
    method = await load('configuration-contract-method-resource.json');
  const wallet = await load('cigl-wallet.json');
  assert.equal(target.state, 'ACTIVE_MATCHED');
  assert.equal(target.activeGenerationDigest, target.desiredGenerationDigest);
  output(
    action('ACT-CIGL_ANALYSES_CREATE_RESOURCE-V1', args[0], {
      definition: {
        targetRuntimeId: target.targetId,
        expectedGenerationDigest: target.activeGenerationDigest,
        runtimeBindingId: method.runtimeBindingId,
        contractMethodPolicyId: method.contractMethodPolicyId,
        expectedRuntimeBindingRevision: '1',
        expectedMethodRevision: method.revision,
        workloadId: args[1],
        transactionHash: wallet.transactionHash,
        expiresInSeconds: 300,
      },
    }),
  );
} else if (mode === 'observe') {
  output(
    action('ACT-CIGL_ANALYSES_UPDATE_RESOURCE-V1', args[0], {
      targetRef: args[1],
      expectedRevision: '1',
      signedReceipt: `0x${(await readFile(join(root, 'cigl-target-observation.json'))).toString('hex')}`,
    }),
  );
} else if (mode === 'review') {
  const analysis = await load('cigl-analysis-observed.json');
  assert.equal(analysis.state, 'OBSERVED');
  assert.equal(analysis.runtimePermission, 'NONE');
  assert.equal(analysis.observation.unresolvedCount, 0);
  assert.equal(analysis.observation.actions.length, 1);
  output(
    action('ACT-CIGL_ANALYSES_REVIEW_RESOURCE-V1', args[0], {
      targetRef: analysis.analysisId,
      expectedRevision: '2',
      review: {
        analysisDigest: analysis.observation.analysisDigest,
        actions: analysis.observation.actions.map(({ actionDigest }) => ({
          actionDigest,
          maximumValue: Array(32).fill(0),
        })),
        program: null,
      },
    }),
  );
} else if (mode === 'grant') {
  const method = await load('configuration-contract-read-b-resource.json');
  output(
    action('ACT-CIGL_GRANTS_CREATE_RESOURCE-V1', args[0], {
      definition: {
        runtimeBindingId: method.runtimeBindingId,
        selector: method.selector,
        subject: { kind: 'WORKLOAD', id: args[1] },
        surface: 'RAW_SUBMISSION',
        effect: 'ALLOW',
      },
      expectedRuntimeBindingRevision: '1',
      expectedMethodRevision: method.revision,
    }),
  );
} else if (mode === 'grant-status') {
  output(
    action('ACT-CIGL_GRANTS_UPDATE_RESOURCE-V1', args[0], {
      targetRef: args[1],
      expectedRevision: args[2],
      status: args[3],
    }),
  );
} else if (mode === 'activation') {
  const { review } = await load(args[1] ?? 'cigl-analysis-compiled.json');
  assert.equal(review.profileCompilation, 'COMPILED');
  const { currentSources: source, result, ...profile } = review.profile;
  assert.equal(result.methodCount, 2);
  assert.equal(result.grantCount, 1);
  assert.ok(source);
  output(
    action('ACT-CIGL_PROFILES_ACTIVATE_RESOURCE-V1', args[0], {
      targetRef: source.targetRuntimeId,
      expectedRevision: source.targetRevision,
      expectedGenerationDigest: source.installedCapsuleDigest,
      participantEpoch: source.participantEpoch,
      profiles: [
        {
          profileId: profile.profileId,
          profileRevision: profile.revision,
          profileDigest: result.profileDigest,
          compilationArtifactDigest: result.artifactDigest,
          grantSourcesDigest: source.grantSourcesDigest,
        },
      ],
    }),
  );
} else if (mode === 'active') {
  const before = await load(args[0] ?? 'cigl-base-target.json'),
    target = await load(args[1] ?? 'cigl-active-target.json');
  assert.equal(target.state, 'ACTIVE_MATCHED');
  assert.equal(target.activeGenerationDigest, target.desiredGenerationDigest);
  assert.notEqual(target.activeGenerationDigest, before.activeGenerationDigest);
  const receipt = await load(args[2] ?? 'cigl-activation-operation.json');
  assert.equal(receipt.state, 'SUCCEEDED');
  assert.equal(receipt.truthState, 'SUCCESS');
} else if (mode === 'installed-lineage') {
  const original = (await load('cigl-analysis-compiled.json')).review.profile;
  const installed = (await load(args[0] ?? 'cigl-installed-analysis.json')).review.profile;
  const target = await load(args[1] ?? 'cigl-active-target.json');
  assert.deepEqual(installed.result, original.result);
  assert.equal(installed.profileId, original.profileId);
  assert.equal(installed.revision, original.revision);
  assert.equal(installed.currentSources?.installedCapsuleDigest, target.activeGenerationDigest);
  assert.notEqual(
    installed.currentSources.installedCapsuleDigest,
    original.currentSources.installedCapsuleDigest,
  );
} else if (mode === 'denied') {
  const response = await load(args[0]);
  assert.equal(response.error?.data?.pcCode, 'PC-RUNTIME-3001', JSON.stringify(response));
  assert.equal(response.error.data.truthState, 'DENIED');
} else if (mode === 'submitted') {
  const response = await load(args[0] ?? 'cigl-submitted.json');
  assert.equal(response.result?.state, 'ACCEPTED', JSON.stringify(response));
  assert.equal(response.result.truthState, 'UNKNOWN');
  assert.equal(
    response.result.signedTransactionHash,
    (await load(args[1] ?? 'cigl-wallet.json')).transactionHash,
  );
  assert.match(response.result.operationId, /^urn:openpc:operation:/u);
} else if (mode === 'postmine') {
  const submitted = (await load('cigl-submitted.json')).result;
  const status = (await load(args[0])).result;
  assert.equal(status.operationId, submitted.operationId);
  assert.equal(status.signedTransactionHash, submitted.signedTransactionHash);
  assert.equal(status.state, 'CONFIRMED');
  assert.equal(status.truthState, 'SUCCESS');
  assert.notEqual(status.evidenceDigest, submitted.evidenceDigest);
  const bytes = await readFile(args[1]);
  const matches = [];
  for (let offset = 0; offset < bytes.length;) {
    const size = bytes.readUInt32BE(offset);
    assert.ok(size > 0 && size <= 1024 * 1024);
    const frame = JSON.parse(bytes.subarray(offset + 4, offset + 4 + size).toString('utf8'));
    offset += 4 + size;
    if (frame.record.command_id !== submitted.operationId.split(':').at(-1)) continue;
    const comparison = frame.record.observation?.state?.cigl_post_mine;
    if (comparison) {
      assert.notEqual(comparison.expected_path_digest, comparison.observed_path_digest);
      assert.equal(
        comparison.profile_digest,
        frame.record.submission_admission.cigl_post_mine.profile_digest,
      );
      assert.equal(frame.record.reconciliation_method, 'EXACT_TRANSACTION_OBSERVATION');
      assert.ok(frame.record.event_digest);
      matches.push(comparison);
    }
  }
  assert.equal(matches.length, 1, 'one durable divergence, including after restart');
  assert.equal(bytes.includes(Buffer.from('structLogs')), false);
  assert.equal(bytes.includes(Buffer.from((await load('cigl-wallet.json')).calldata)), false);
} else if (mode === 'replayed') {
  assert.deepEqual(await load(args[0]), await load(args[1] ?? 'cigl-submitted.json'));
} else if (mode === 'one-send-per-hash') {
  const submissions = (await readFile(args[0], 'utf8')).trim().split('\n').map(JSON.parse);
  const expected = await Promise.all(
    args.slice(1).map(async (name) => (await load(name)).transactionHash),
  );
  assert.equal(new Set(expected).size, expected.length);
  assert.deepEqual(
    submissions.map(({ transactionHash }) => transactionHash).sort(),
    expected.sort(),
  );
} else if (mode === 'no-submission-preflight') {
  const requests = (await readFile(args[0], 'utf8')).trim().split('\n').slice(Number(args[1]));
  // The background exact-hash observer may continue independently. New
  // submission preflight I/O would make a nonce/fee denial a false revocation pass.
  for (const line of requests) {
    const { method } = JSON.parse(line);
    assert.ok(
      ['eth_getTransactionReceipt', 'eth_getTransactionByHash'].includes(method),
      `revoked submission contacted provider: ${method}`,
    );
  }
} else {
  throw Error('Unknown CIGL journey input');
}
