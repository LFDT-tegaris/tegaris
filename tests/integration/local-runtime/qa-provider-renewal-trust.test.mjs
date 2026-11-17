import assert from 'node:assert/strict';
import test from 'node:test';
import { supplementProviderRenewalTrust } from './qa-provider-renewal-trust.mjs';

const now = new Date('2026-10-01T08:00:00Z');
const approvalId = '019a08d0-0002-7000-8000-000000000001';
function database({
  source = true,
  request = true,
  failAssignment = false,
  bound = new Date(+now + 3_600_000),
} = {}) {
  const calls = [];
  let envelope, grant, baseline;
  return {
    calls,
    advance(milliseconds) {
      now.setTime(+now + milliseconds);
    },
    corrupt() {
      grant[8] = ['ACT-UNRELATED-V1'];
    },
    async query(sql, args = []) {
      calls.push({ sql, args });
      if (sql.startsWith('begin')) baseline = [envelope, grant];
      if (sql === 'rollback') [envelope, grant] = baseline;
      if (sql.includes('from control.provider_profile'))
        return { rowCount: source ? 1 : 0, rows: source ? [{ now, bound }] : [] };
      if (sql.includes('from control.approval_request'))
        return { rowCount: request ? 1 : 0, rows: [] };
      if (sql.startsWith('insert into control.authority_envelope')) envelope = args;
      if (sql.startsWith('insert into control.assignment')) {
        if (failAssignment) throw new Error('assignment rejected');
        grant = args;
      }
      if (sql.includes('from control.authority_envelope e left join')) {
        if (!envelope) return { rows: [] };
        const [
          ,
          ,
          principal,
          ,
          ,
          validFrom,
          validUntil,
          semantic,
          digest,
          cose,
          privacy,
          actions,
          resources,
          platform,
        ] = envelope;
        return {
          rows: [
            {
              principal,
              representation: 'LEGACY',
              state: 'ACTIVE',
              validFrom,
              validUntil,
              semantic,
              digest,
              cose,
              privacy,
              actions,
              resources,
              risks: ['HIGH'],
              capabilities: [],
              makerChecker: true,
              stepUp: true,
              depth: 0,
              platform,
              epoch: '1',
              assignment: grant?.[0],
              assignedPrincipal: grant?.[2],
              assignmentState: 'ACTIVE',
              role: null,
              scopeDigest: grant?.[4],
              assignmentFrom: grant?.[5],
              assignmentUntil: grant?.[6],
              assignmentPrivacy: grant?.[7],
              assignmentActions: grant?.[8],
              assignmentResources: grant?.[9],
              assignmentRisks: ['HIGH'],
              assignmentCapabilities: [],
              assignmentMakerChecker: true,
              assignmentStepUp: true,
              assignmentDepth: 0,
            },
          ],
        };
      }
      return { rows: [], rowCount: 1 };
    },
  };
}
test('maker supplement has only finite provider update trust, without runtime or delegation', async () => {
  const db = database();
  const result = await supplementProviderRenewalTrust(db, { phase: 'maker', revision: '8' });
  assert.equal(result.fixture, 'SYNTHETIC_LOCAL_QA_PROVIDER_RENEWAL');
  assert.deepEqual(result.actions, ['ACT-PROVIDER_PROFILES_UPDATE_RESOURCE-V1']);
  assert.deepEqual(result.resources, ['01a0f4e2-a2af-7371-8ca3-d63c500c4373']);
  assert.equal(result.validUntil, '2026-10-01T09:00:00.000Z');
  assert.equal(db.calls.at(-1).sql, 'commit');
  assert.equal(db.calls.filter(({ sql }) => sql.startsWith('insert')).length, 2);
});
test('checker trust binds approval and business action to the same exact grant', async () => {
  const db = database();
  const result = await supplementProviderRenewalTrust(db, {
    phase: 'checker',
    revision: '8',
    approvalId,
  });
  assert.deepEqual(result.actions, [
    'ACT-PROVIDER_PROFILES_UPDATE_RESOURCE-V1',
    'ACT-POLICY_APPROVE_REQUEST-V1',
  ]);
  assert.deepEqual(result.resources, ['01a0f4e2-a2af-7371-8ca3-d63c500c4373', approvalId]);
  assert.ok(
    db.calls.some(
      ({ sql, args }) => sql.includes('from control.approval_request') && args[0] === approvalId,
    ),
  );
});
test('credential expiry shortens authority and exact replay inserts nothing', async () => {
  const db = database({ bound: new Date(+now + 30_000) });
  const input = { phase: 'maker', revision: '8' };
  assert.equal(
    (await supplementProviderRenewalTrust(db, input)).validUntil,
    new Date(+now + 30_000).toISOString(),
  );
  assert.equal((await supplementProviderRenewalTrust(db, input)).replay, true);
  assert.equal(db.calls.filter(({ sql }) => sql.startsWith('insert')).length, 2);
});
test('expired or modified trust cannot be renewed by replay', async () => {
  const expired = database({ bound: new Date(+now + 30_000) });
  const input = { phase: 'maker', revision: '8' };
  await supplementProviderRenewalTrust(expired, input);
  expired.advance(31_000);
  await assert.rejects(supplementProviderRenewalTrust(expired, input));
  expired.advance(-31_000);
  const modified = database();
  await supplementProviderRenewalTrust(modified, input);
  modified.corrupt();
  await assert.rejects(supplementProviderRenewalTrust(modified, input), /readback/u);
});
test('stale provider, invalid credentials and consumed or mismatched proposals cause no writes', async () => {
  for (const settings of [{ source: false }, { request: false }, { bound: now }]) {
    const db = database(settings);
    await assert.rejects(
      supplementProviderRenewalTrust(db, { phase: 'checker', revision: '8', approvalId }),
    );
    assert.equal(db.calls.filter(({ sql }) => sql.startsWith('insert')).length, 0);
    assert.equal(db.calls.at(-1).sql, 'rollback');
  }
});
test('assignment failure rolls back the envelope and fails closed', async () => {
  const db = database({ failAssignment: true });
  await assert.rejects(
    supplementProviderRenewalTrust(db, { phase: 'maker', revision: '8' }),
    /assignment rejected/u,
  );
  assert.equal(db.calls.at(-1).sql, 'rollback');
  assert.deepEqual((await db.query('from control.authority_envelope e left join')).rows, []);
});
test('caller cannot widen the fixed fixture scope', async () => {
  for (const input of [
    { phase: 'maker', revision: '8', resources: ['*'] },
    { phase: 'other', revision: '8' },
    { phase: 'checker', revision: '8', approvalId: '*' },
  ]) {
    const db = database();
    await assert.rejects(supplementProviderRenewalTrust(db, input));
    assert.equal(db.calls.length, 0);
  }
});

test('a later current provider revision appends separate trust and cannot widen an old replay', async () => {
  const old = await supplementProviderRenewalTrust(database(), { phase: 'maker', revision: '8' });
  const db = database();
  const fresh = await supplementProviderRenewalTrust(db, { phase: 'maker', revision: '12' });
  assert.notEqual(fresh.envelopeId, old.envelopeId);
  assert.notEqual(fresh.assignmentId, old.assignmentId);
  assert.deepEqual(fresh.actions, old.actions);
  assert.deepEqual(fresh.resources, old.resources);
  assert.equal(fresh.validUntil, old.validUntil);
  const replay = await supplementProviderRenewalTrust(db, { phase: 'maker', revision: '12' });
  assert.equal(replay.replay, true);
  assert.equal(replay.envelopeId, fresh.envelopeId);
  await assert.rejects(supplementProviderRenewalTrust(db, { phase: 'maker', revision: '13' }));
});
