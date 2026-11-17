import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
const [mode, root, token, participantId, privacyDomainId, roleId, assignmentId] =
  process.argv.slice(2);
assert.ok(['active', 'restarted', 'stale', 'archived'].includes(mode));
const base = `http://127.0.0.1:8080/v1/participants/${participantId}`;
async function get(path, privacy = privacyDomainId) {
  const response = await fetch(`${base}/${path}`, {
    headers: {
      'Authorization': `Bearer ${token}`,
      'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacy}`,
    },
    signal: AbortSignal.timeout(5000),
  });
  assert.equal(response.headers.get('cache-control'), 'no-store');
  return { status: response.status, body: await response.json() };
}
const hidden = { status: 404, body: { error: { code: 'PC-IDENTITY-1008', status: 404 } } };
const role = await get(`roles/${roleId}`);
if (mode === 'stale') {
  assert.deepEqual(role, hidden);
} else {
  assert.equal(role.status, 200, JSON.stringify(role.body));
  assert.equal(role.body.effect.id, roleId);
  assert.equal(role.body.effect.roleId, `urn:openpc:role:${roleId}`);
  assert.equal(role.body.effect.displayName, 'Participant auditors');
  assert.equal(role.body.effect.origin, 'GOVERNED');
  assert.deepEqual(role.body.effect.actionIntentIds, ['ACT-PARTICIPANTS_READ_RESOURCE-V1']);
  assert.equal(role.body.effect.state, mode === 'archived' ? 'ARCHIVED' : 'ACTIVE');
  assert.equal(role.body.effect.revision, mode === 'archived' ? '2' : '1');
  assert.match(role.body.operationId, /^[0-9a-f-]{36}$/u);
  const path = join(root, 'role-authoritative-readback.json');
  if (mode === 'active') await writeFile(path, JSON.stringify(role.body));
  if (mode === 'restarted') assert.deepEqual(role.body, JSON.parse(await readFile(path, 'utf8')));
  if (mode === 'archived') {
    const assignment = await get(`assignments/${assignmentId}`);
    assert.equal(assignment.status, 200, JSON.stringify(assignment.body));
    assert.equal(assignment.body.effect.state, 'REVOKED');
    assert.equal(assignment.body.revision, '2');
    assert.equal(assignment.body.operationId, role.body.operationId);
    const result = JSON.parse(await readFile(join(root, 'role-archived.json'), 'utf8'));
    assert.deepEqual(result.effect, role.body.effect);
    assert.equal(result.revokedAssignments, 1);
  }
  assert.deepEqual(await get(`roles/${roleId}`, '018f0000-0000-7000-8000-000000000299'), hidden);
  assert.deepEqual(await get('roles/018f0000-0000-7000-8000-000000000899'), hidden);
}
process.stdout.write(`OPENPC_ROLE_READBACK|PASS|${mode}\n`);
