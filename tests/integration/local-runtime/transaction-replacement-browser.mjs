import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { expect } from '@playwright/test';

export async function replacementSendCounts(evidenceRoot, dataRoot) {
  const entries = (
    await readFile(join(dataRoot, 'rpc-provider/deployment-submissions.jsonl'), 'utf8')
  )
    .trim()
    .split('\n')
    .filter(Boolean)
    .map(JSON.parse);
  return Promise.all(
    ['original', 'bump', 'second'].map(async (name) => {
      const wallet = JSON.parse(
        await readFile(join(evidenceRoot, `deployment-wallet-replacement-${name}.json`), 'utf8'),
      );
      return entries.filter((entry) => entry.transactionHash === wallet.transactionHash).length;
    }),
  );
}

export async function replacePendingDeployment({
  govern,
  readApproval,
  actors,
  original,
  originalApprovalId,
  originalWallet,
  evidenceRoot,
  dataRoot,
  deploymentPolicyId,
  runtimeTargetId,
  walletId,
  leaseExpiryNs,
}) {
  const operationId = original.candidate.operationRef.slice(-36);
  // The real replacement command synchronously obtains a fresh exact-hash
  // observation. It does not depend on the background observer's round-robin
  // schedule or an earlier actor's journal-read permissions.
  const loadWallet = async (name) =>
    JSON.parse(
      await readFile(join(evidenceRoot, `deployment-wallet-replacement-${name}.json`), 'utf8'),
    );
  const bump = await loadWallet('bump');
  const second = await loadWallet('second');
  const intentFields = (wallet) => ({
    'Deployment policy reference': deploymentPolicyId,
    'Runtime target reference': runtimeTargetId,
    'Wallet binding reference': `urn:openpc:resource:${walletId}`,
    'Execution workload reference (optional)':
      'urn:openpc:workload:018f0000-0000-7000-8000-000000000191',
    'Unsigned transaction bytes': wallet.signingPayload,
  });
  const prepared = await govern({
    ...actors,
    label: 'Prepare deployment',
    fields: intentFields(bump),
    reason: `Prepare the independently approved fee increase for ${operationId}.`,
  });
  assert.equal(prepared.completed.result.expectedContractAddress, originalWallet.expectedAddress);
  assert.equal(prepared.completed.result.signingPayload, bump.signingPayload);
  const scenarioPath = join(dataRoot, 'rpc-provider', 'deployment-scenario.json');
  const scenario = JSON.parse(await readFile(scenarioPath, 'utf8'));
  assert.equal(scenario.wallet.transactionHash, originalWallet.transactionHash);
  scenario.replacement = bump;
  await writeFile(scenarioPath, JSON.stringify(scenario), { mode: 0o600 });
  const successor = await govern({
    ...actors,
    label: 'Submit signed deployment',
    fields: {
      'Deployment intent reference': prepared.completed.candidate.resourceRef,
      'Signed transaction bytes': bump.signedTransaction,
      'Predecessor operation reference (optional)': original.candidate.operationRef,
    },
    reason: `Execute the single independently approved successor of ${operationId}.`,
    loseExecutionResponse: true,
  });
  assert.equal(
    successor.review.candidate.candidate.predecessorOperationId,
    original.candidate.operationRef,
  );
  let current;
  await expect
    .poll(
      async () => {
        current = await readApproval(actors.maker, successor.approvalId);
        return current.result?.attempt?.signedTransactionHash;
      },
      { timeout: 20_000, intervals: [100, 250, 500] },
    )
    .toBe(bump.transactionHash.slice(2));
  assert.equal(current.result.state, 'WRITE_AMBIGUITY');

  const secondPreparation = await govern({
    ...actors,
    label: 'Prepare deployment',
    fields: intentFields(second),
    reason: `Prepare a distinct fee increase to test the one-successor limit for ${operationId}.`,
  });
  assert.ok(
    BigInt(leaseExpiryNs) > BigInt(Date.now() + 3000) * 1_000_000n,
    'second-successor denial requires unexpired runtime authority',
  );
  const denied = await govern({
    ...actors,
    label: 'Submit signed deployment',
    fields: {
      'Deployment intent reference': secondPreparation.completed.candidate.resourceRef,
      'Signed transaction bytes': second.signedTransaction,
      'Predecessor operation reference (optional)': original.candidate.operationRef,
    },
    reason: `Deny a second successor even with independent approval for ${operationId}.`,
    expectedExecutionStatus: 404,
  });
  assert.equal(denied.problem.code, 'PC-AUTH-0005');
  assert.equal(denied.problem.truthState, 'DENIED');
  assert.ok(
    BigInt(leaseExpiryNs) > BigInt(denied.executionObservedAtMs) * 1_000_000n,
    'denial must precede runtime expiry',
  );
  const counts = () => replacementSendCounts(evidenceRoot, dataRoot);
  assert.deepEqual(await counts(), [1, 1, 0]);
  const predecessor = await readApproval(actors.maker, originalApprovalId);
  assert.equal(predecessor.candidate.operationRef, original.candidate.operationRef);
  assert.deepEqual(predecessor.result.attempt, original.result.attempt);
  return { successor, current, predecessor, originalApprovalId, counts };
}
