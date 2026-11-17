import assert from 'node:assert/strict';
import { lstat } from 'node:fs/promises';
import { join } from 'node:path';

export async function requireNewRetirementObservation(output, name) {
  try {
    await lstat(join(output, `${name}.json`));
  } catch (error) {
    if (error.code === 'ENOENT') return;
    throw error;
  }
  throw new Error(`Existing ${name} observation requires public reconciliation before mutation`);
}

/** Public readback selects the current attempt; saved observations confer no authority. */
export async function readRuntimeRetirementApprovalChain(read, originalApproval, expected) {
  const seen = new Set();
  let approvalId = originalApproval;
  for (;;) {
    assert.match(
      approvalId,
      /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
    );
    assert.ok(seen.size < 32 && !seen.has(approvalId), 'Invalid retirement approval chain');
    seen.add(approvalId);
    const current = await read(approvalId);
    assert.equal(current.kind, 'evidence-deletion-runtime');
    assert.deepEqual(current.candidate.candidate, expected.body);
    assert.equal(current.candidate.businessIdempotencyKey, expected.key);
    assert.equal(current.candidate.resourceRef, expected.resourceRef);
    const successor = current.candidate.successorApprovalRef;
    if (!successor) return { approvalId, current };
    assert.equal(
      current.candidate.operationRef,
      null,
      'Consumed retirement cannot have a successor',
    );
    assert.match(successor, /^urn:openpc:resource:/u);
    approvalId = successor.slice('urn:openpc:resource:'.length);
  }
}
