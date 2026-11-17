import assert from 'node:assert/strict';
import { readFactActivationDisposition } from './target-disposition-readback.mjs';

/** Compose with the existing fresh-source/public-policy/RPC fixture. No new
 * producer, intermediate business writes, authority renewal or effect replay. */
export async function factTargetActivationAcceptance({
  secretRoot,
  participantId,
  privacyDomainId,
  discovery,
  fact,
  rpc,
}) {
  assert.equal(typeof rpc, 'function', 'The real RPC custody journey is mandatory');
  assert.ok(
    Number.isSafeInteger(fact.freshUntilMs) && fact.freshUntilMs > Date.now(),
    'Original Fact must still be live before the existing RPC path',
  );
  const original = await readFactActivationDisposition({
    secretRoot,
    participantId,
    privacyDomainId,
    targetId: discovery.targetId,
    fact,
  });
  process.stdout.write(
    'OPENPC_TARGET_FACT_DISPOSITION|PASS|signed-confirmation-and-ack|original-public-activation\n',
  );
  // The RPC owner performs the actual mTLS, policy, Fact and per-use target
  // currentness checks. Readback above cannot replace its serving decision.
  await rpc();
  return original;
}

/** The caller owns the real service restart/recovery. Supplying its original
 * in-memory result compares every chain byte and effect identity afterward. */
export async function factTargetRestartReadback({ prior, ...input }) {
  assert.ok(prior, 'Restart comparison requires the original readback');
  const original = await readFactActivationDisposition({ ...input, prior });
  process.stdout.write(
    'OPENPC_TARGET_FACT_DISPOSITION|PASS|historical-restart-readback|no-renewal-no-effect-replay\n',
  );
  return original;
}
