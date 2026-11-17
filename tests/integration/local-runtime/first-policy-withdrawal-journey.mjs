import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { releaseFirstPolicy } from './first-policy-workbench-browser.mjs';
import { readInitialActivationDisposition } from './target-disposition-readback.mjs';
import {
  recoverExpiredTargetDisposition,
  waitForDispositionExpiry,
} from './target-disposition-recovery.mjs';

const [secretRoot, evidenceRoot] = process.argv.slice(2);
const read = async (name) => JSON.parse(await readFile(join(evidenceRoot, name), 'utf8'));
const initial = await read('first-policy-release-checkpoint.json');
assert.ok(initial.activeOccurrence && initial.activePolicySet);
assert.equal(
  initial.targetRenewal,
  undefined,
  'Fresh independent case only; use original recovery after interruption',
);
const input = await read('policy-set-input.json');
const discovery = await read('discovery-credential-input.json');
const options = {
  secretRoot,
  participantId: input.participantId,
  privacyDomainId: input.privacyDomainId,
  targetId: discovery.targetId,
};
const original = await readInitialActivationDisposition(options);
await waitForDispositionExpiry(original);
const browser = {
  secretRoot,
  evidenceRoot,
  inputPath: join(evidenceRoot, 'policy-set-input.json'),
  journey: 'first-policy',
};
// The existing public renewal owner acquires fresh workload authority, then
// verifies the signed withdrawal/successor and live restart before visual work.
await releaseFirstPolicy(browser);
const renewed = await read('first-policy-release-checkpoint.json');
assert.ok(renewed.targetRenewal?.operation?.operationId && renewed.targetRenewal.target);
assert.equal(renewed.targetRenewal.successorOf, undefined);
const successorOptions = {
  ...options,
  renewalOperationId: renewed.targetRenewal.operation.operationId,
};
const successor = await readInitialActivationDisposition(successorOptions);
assert.equal(successor.chain.length, 3);
assert.deepEqual(successor.chain[0], original.chain[0]);
await waitForDispositionExpiry(successor);
await recoverExpiredTargetDisposition(
  successorOptions,
  JSON.parse(process.env.OPENPC_POLICY_SET_COMPOSE_JSON),
  () => releaseFirstPolicy({ ...browser, historicalReadbackOnly: true }),
);
process.stdout.write(
  'OPENPC_FIRST_POLICY_WITHDRAWAL|PASS|independent-public-renewal|signed-withdrawal-ACK|live-restart|expiry-denial|historical-recovery-browser\n',
);
