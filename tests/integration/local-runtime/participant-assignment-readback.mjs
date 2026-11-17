import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

const [mode, evidenceRoot, sessionToken, participantId, privacyDomainId, assignmentId] =
  process.argv.slice(2);
assert.ok(['before-restart', 'after-restart'].includes(mode));
assert.ok(sessionToken && evidenceRoot && participantId && privacyDomainId && assignmentId);
const url = `http://127.0.0.1:8080/v1/participants/${participantId}/assignments/${assignmentId}`;
const get = async (target = url, privacy = `urn:openpc:privacy-domain:${privacyDomainId}`) => {
  const response = await fetch(target, {
    headers: { 'authorization': `Bearer ${sessionToken}`, 'openpc-privacy-domain-id': privacy },
    signal: AbortSignal.timeout(5_000),
  });
  return { status: response.status, body: await response.json() };
};
const response = await get();
assert.equal(response.status, 200, JSON.stringify(response.body));
assert.equal(response.body.effect.id, assignmentId);
assert.equal(response.body.effect.roleId, 'urn:openpc:role:018f0000-0000-7000-8000-000000000801');
assert.equal(response.body.effect.state, 'ACTIVE');
assert.deepEqual(response.body.effect.capabilityIds, ['CALL_RESULT_DISCLOSURE']);
assert.deepEqual(response.body.effect.privacyDomainIds, [privacyDomainId]);
assert.equal(response.body.revision, '1');
assert.match(response.body.operationId, /^[0-9a-f-]{36}$/u);
const previousPath = join(evidenceRoot, 'participant-assignment-authoritative-readback.json');
if (mode === 'before-restart') {
  await writeFile(previousPath, JSON.stringify(response.body));
} else {
  assert.deepEqual(response.body, JSON.parse(await readFile(previousPath, 'utf8')));
}
const hidden = { status: 404, body: { error: { code: 'PC-IDENTITY-1008', status: 404 } } };
assert.deepEqual(await get(url, `urn:openpc:participant:${privacyDomainId}`), hidden);
assert.deepEqual(
  await get(url, 'urn:openpc:privacy-domain:018f0000-0000-7000-8000-000000000299'),
  hidden,
);
assert.deepEqual(
  await get(url.replace(assignmentId, '018f0000-0000-7000-8000-000000000199')),
  hidden,
);
assert.deepEqual(
  await get(url.replace(participantId, '018f0000-0000-7000-8000-000000000199')),
  hidden,
);
process.stdout.write(
  `OPENPC_ASSIGNMENT_READBACK|PASS|${mode}|stored-role|exact-scope|operation|hidden-equivalence\n`,
);
