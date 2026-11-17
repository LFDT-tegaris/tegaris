import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

import { Pool } from 'pg';
import { bootstrapPrivacyAuthority } from './privacy-authority-fixture.mjs';

import {
  buildPolicyService,
  HttpPolicyIdentityGateway,
} from '../../../services/module-registry/src/policy-http.ts';

const [secretRoot, identityUrl, participantId, privacyDomainId, makerId, checkerId, readSession] =
  process.argv.slice(2);
const origin = 'http://127.0.0.1:8080';
const secret = async (name) => (await readFile(join(secretRoot, `${name}.txt`), 'utf8')).trim();
const connection = { host: '127.0.0.1', port: 55432, database: 'openpc_control', max: 2 };
const admin = new Pool({
  ...connection,
  user: 'openpc_control',
  password: await secret('control_pg_password'),
});
const runtime = new Pool({
  ...connection,
  user: 'openpc_policy_runtime',
  password: await secret('policy_runtime_db_password'),
});
const gateway = new HttpPolicyIdentityGateway(identityUrl, await secret('identity_internal_token'));
const approvalActionId = 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1';
const approvalActionDigest = (
  await admin.query(
    `select 'sha256:'||encode(semantic_digest,'hex') digest from control.action_intent where action_intent_id=$1`,
    [approvalActionId],
  )
).rows[0].digest;

function uuid() {
  const bytes = randomBytes(16);
  bytes.writeUIntBE(Date.now(), 0, 6);
  bytes[6] = (bytes[6] & 15) | 112;
  bytes[8] = (bytes[8] & 63) | 128;
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

// Independent wire canonicalization for public command digests.
function canonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`)
    .join(',')}}`;
}
const digest = (value) => `sha256:${createHash('sha256').update(canonical(value)).digest('hex')}`;

function barrier() {
  const arrived = Promise.withResolvers();
  const released = Promise.withResolvers();
  return {
    arrived: arrived.promise,
    release: released.resolve,
    async wait(value) {
      arrived.resolve(value);
      await released.promise;
    },
  };
}

async function bounded(promise, label) {
  const abort = new AbortController();
  try {
    return await Promise.race([
      promise,
      delay(15_000, undefined, { signal: abort.signal }).then(() => {
        throw new Error(`${label} timed out`);
      }),
    ]);
  } finally {
    abort.abort();
  }
}

async function login() {
  // Initial trust only; all tested approval and revocation state uses its real owner.
  const response = await fetch(`${identityUrl}/internal/v1/local/session/login`, {
    method: 'POST',
    headers: {
      'authorization': `Bearer ${await secret('identity_internal_token')}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      role: 'operator',
      credential: await secret('local_operator_credential'),
    }),
    signal: AbortSignal.timeout(15_000),
  });
  assert.equal(response.status, 201, 'initial test identity login');
  return (await response.json()).sessionToken;
}

async function csrf(session, actionIntentId) {
  const response = await fetch(`${origin}/api/v1/session/csrf`, {
    method: 'POST',
    headers: {
      origin,
      'cookie': `__Host-openpc_session=${session}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify({ actionIntentId }),
    signal: AbortSignal.timeout(15_000),
  });
  assert.equal(response.status, 200, 'public CSRF');
  return (await response.json()).csrfToken;
}

function headers(session, key) {
  return {
    'host': '127.0.0.1:8080',
    origin,
    'cookie': `__Host-openpc_session=${session}`,
    'content-type': 'application/json',
    'openpc-api-version': '1',
    'openpc-participant-id': `urn:openpc:participant:${participantId}`,
    'openpc-privacy-domain-id': `urn:openpc:privacy-domain:${privacyDomainId}`,
    'x-request-id': uuid(),
    'x-correlation-id': uuid(),
    'idempotency-key': key,
  };
}

async function logoutRequest(session, key) {
  const sessionId = session.split('.')[1];
  const actionIntentId = 'ACT-IDENTITY_DELETE_SESSION-V1';
  const actionIntentDigest = (
    await admin.query(
      `select 'sha256:'||encode(semantic_digest,'hex') digest from control.action_intent where action_intent_id=$1`,
      [actionIntentId],
    )
  ).rows[0].digest;
  const expectedRevision = (
    await admin.query(
      'select row_version::text revision from control.session where participant_id=$1 and session_id=$2',
      [participantId, sessionId],
    )
  ).rows[0].revision;
  const reason = 'Revoke this session through its supported owner during the authority race.';
  const body = {
    actionIntentId,
    actionIntentDigest,
    expectedRevision,
    targetRef: `urn:openpc:resource:${sessionId}`,
    inputDigest: digest({ sessionId, reason }),
    reason,
  };
  const requestHeaders = {
    ...headers(session, key),
    'x-csrf-token': await csrf(session, actionIntentId),
    'openpc-action-intent-digest': actionIntentDigest,
    'if-match': `"${digest({ resourceType: 'session', sessionId, revision: expectedRevision })}"`,
  };
  return () =>
    fetch(`${origin}/api/v1/session/logout`, {
      method: 'POST',
      headers: requestHeaders,
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(15_000),
    });
}

async function waitForBlockedSession(writerPid) {
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    const blocked = await admin.query(
      `select pid from pg_stat_activity where datname=current_database() and wait_event_type='Lock'
          and $1=any(pg_blocking_pids(pid)) and query ilike '%control.session%'`,
      [writerPid],
    );
    if (blocked.rowCount > 0) return;
    await delay(25);
  }
  throw new Error('session revocation did not wait for committing authority reader');
}

async function freshApprovalCandidate(session, label) {
  const actionIntentId = 'ACT-LOGICAL_CONTRACT_ASSETS_CREATE_RESOURCE-V1';
  const actionIntentDigest = (
    await admin.query(
      `select 'sha256:'||encode(semantic_digest,'hex') digest from control.action_intent where action_intent_id=$1`,
      [actionIntentId],
    )
  ).rows[0].digest;
  const candidate = {
    actionIntentId,
    actionIntentDigest,
    logicalName: `${label}-${uuid()}`,
    displayName: `Authority acceptance ${label}`,
    reason: `Propose an independent logical contract for ${label}.`,
  };
  const response = await fetch(`${origin}/api/v1/logical-contract-assets`, {
    method: 'POST',
    headers: {
      ...headers(session, `candidate-${uuid()}`),
      'x-csrf-token': await csrf(session, actionIntentId),
      'openpc-action-intent-digest': actionIntentDigest,
    },
    body: JSON.stringify(candidate),
    signal: AbortSignal.timeout(15_000),
  });
  assert.equal(response.status, 403, await response.clone().text());
  const staged = await admin.query(
    `select candidate.state,candidate.maker_session_id::text session,
       (select count(*)::int from control.logical_contract_asset resource
         where resource.participant_id=candidate.participant_id
           and resource.logical_contract_id=candidate.resource_id) effects
     from control.mutation_candidate candidate
     where candidate.participant_id=$1 and candidate.privacy_domain_id=$2
       and candidate.candidate_digest=$3`,
    [participantId, privacyDomainId, Buffer.from(digest(candidate).slice(7), 'hex')],
  );
  assert.deepEqual(staged.rows, [
    { state: 'PROPOSED', session: session.split('.')[1], effects: 0 },
  ]);
  return {
    actionIntentId: approvalActionId,
    actionIntentDigest: approvalActionDigest,
    makerSubjectRef: `urn:openpc:resource:${makerId}`,
    checkerSubjectRef: `urn:openpc:resource:${checkerId}`,
    candidateDigest: digest(candidate),
    reason: `Request approval of the exact public proposal for ${label}.`,
  };
}

async function selectPrivacyContext(session, privacy) {
  const fixture = JSON.parse(
    await readFile(
      join(secretRoot, '..', 'evidence', 'configuration-identity-fixture.json'),
      'utf8',
    ),
  ).operator;
  const actionIntentId = 'ACT-IDENTITY_CREATE_SESSION-V1';
  const resourceId = session.split('.')[1];
  const resourceDigest = digest({ sessionId: resourceId, privacyDomainId: privacy });
  const rpIdHash = `sha256:${createHash('sha256').update('127.0.0.1').digest('hex')}`;
  const csrfToken = await csrf(session, actionIntentId);
  const challengeResponse = await fetch(`${origin}/v1/identity/webauthn/assertion/challenge`, {
    method: 'POST',
    headers: { ...headers(session, `privacy-challenge-${uuid()}`), 'x-csrf-token': csrfToken },
    body: JSON.stringify({ actionIntentId, resourceId, resourceDigest, rpIdHash }),
    signal: AbortSignal.timeout(15_000),
  });
  assert.equal(challengeResponse.status, 200, await challengeResponse.clone().text());
  const { challenge } = await challengeResponse.json();
  const current = (
    await admin.query(
      `select s.row_version::text revision,
    (c.authenticator_sign_count+1)::text counter,
    'sha256:'||encode(ai.semantic_digest,'hex') digest
    from control.session s join control.credential c on c.participant_id=s.participant_id
      and c.principal_id=s.principal_id and c.credential_id=$3
    cross join control.action_intent ai
    where s.participant_id=$1 and s.session_id=$2 and ai.action_intent_id=$4`,
      [participantId, resourceId, fixture.credentialId, 'ACT-IDENTITY_UPDATE_STEP_UP-V1'],
    )
  ).rows[0];
  assert.ok(current);
  const assertion = execFileSync(
    process.execPath,
    [
      'tests/integration/local-runtime/configuration-fixture.mjs',
      'assertion',
      fixture.privateKeyPath,
      fixture.credentialId,
      challenge,
      origin,
      rpIdHash,
      current.counter,
    ],
    { encoding: 'utf8' },
  );
  const verified = await fetch(`${origin}/v1/identity/webauthn/assertion/verify`, {
    method: 'POST',
    headers: {
      ...headers(session, `privacy-step-up-${uuid()}`),
      'x-csrf-token': csrfToken,
      'x-openpc-aggregate-version': current.revision,
      'openpc-action-intent-digest': current.digest,
    },
    body: JSON.stringify({
      actionIntentId,
      resourceId,
      resourceDigest,
      rpIdHash,
      challenge,
      assertion,
    }),
    signal: AbortSignal.timeout(15_000),
  });
  assert.equal(verified.status, 200, await verified.clone().text());
  const selected = await fetch(`${origin}/api/v1/session/context`, {
    method: 'POST',
    headers: {
      ...headers(session, `privacy-context-${uuid()}`),
      'x-csrf-token': await csrf(session, 'ACT-IDENTITY_CREATE_SESSION-V1'),
    },
    body: JSON.stringify({ participantId, privacyDomainId: privacy }),
    signal: AbortSignal.timeout(15_000),
  });
  assert.equal(selected.status, 201, await selected.clone().text());
  const result = await selected.json();
  assert.equal(result.privacyDomainId, privacy);
  assert.notEqual(result.sessionToken, session);
  return result.sessionToken;
}

async function privacyReadbackAndReplay() {
  const otherPrivacy = uuid();
  const key = `privacy-replay-${uuid()}`;
  const session = await login();
  const body = await freshApprovalCandidate(session, 'privacy-readback');
  const createHeaders = {
    ...headers(session, key),
    'x-csrf-token': await csrf(session, body.actionIntentId),
    'x-openpc-action-intent-digest': body.actionIntentDigest,
  };
  const create = async (privacy, actorSession = session) =>
    fetch(`${origin}/api/v1/approval-requests`, {
      method: 'POST',
      headers: {
        ...createHeaders,
        'cookie': `__Host-openpc_session=${actorSession}`,
        'x-csrf-token': await csrf(actorSession, body.actionIntentId),
        'openpc-privacy-domain-id': `urn:openpc:privacy-domain:${privacy}`,
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(15_000),
    });
  const first = await create(privacyDomainId);
  assert.equal(first.status, 202, await first.clone().text());
  const operation = await first.json();
  assert.notEqual(
    operation.operationId,
    createHeaders['x-request-id'],
    'operation identity is server owned',
  );
  const read = (privacy, operationId = operation.operationId, actorSession = session) =>
    fetch(`${origin}/api/v1/operations/${operationId}`, {
      headers: {
        ...headers(actorSession, key),
        'openpc-privacy-domain-id': `urn:openpc:privacy-domain:${privacy}`,
      },
      signal: AbortSignal.timeout(15_000),
    });
  assert.equal((await read(privacyDomainId)).status, 200);
  const forbidden = await read(otherPrivacy);
  assert.equal(forbidden.status, 403, await forbidden.text());
  const principal = (
    await admin.query(
      'select principal_id from control.session where participant_id=$1 and session_id=$2',
      [participantId, session.split('.')[1]],
    )
  ).rows[0].principal_id;
  await bootstrapPrivacyAuthority(admin, participantId, principal, otherPrivacy, uuid(), uuid(), {
    allowContextSelection: true,
  });
  for (const [privacy, expected] of [
    [privacyDomainId, true],
    [otherPrivacy, false],
  ]) {
    const evaluated = await fetch('http://127.0.0.1:53005/v1/authority/evaluate', {
      method: 'POST',
      headers: { 'authorization': `Bearer ${session}`, 'content-type': 'application/json' },
      body: JSON.stringify({
        privacyDomainId: privacy,
        actionIntentId: 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
        resourceId: 'identity-session',
        riskClass: 'STANDARD',
      }),
      signal: AbortSignal.timeout(15_000),
    });
    assert.equal(evaluated.status, 200, await evaluated.clone().text());
    const decision = await evaluated.json();
    assert.equal(decision.authorized, expected, JSON.stringify(decision));
    assert.equal(decision.terminal, !expected);
  }
  // A different header never switches context, even after the principal gains authority there.
  assert.equal((await read(otherPrivacy)).status, 403);
  const selectedSession = await selectPrivacyContext(await login(), otherPrivacy);
  const hidden = await read(otherPrivacy, operation.operationId, selectedSession);
  assert.equal(hidden.status, 404, await hidden.clone().text());
  const hiddenProblem = await hidden.clone().json();
  const missing = await read(otherPrivacy, uuid(), selectedSession);
  assert.equal(missing.status, 404, await missing.clone().text());
  const missingProblem = await missing.json();
  assert.deepEqual(
    { ...hiddenProblem, traceId: undefined },
    { ...missingProblem, traceId: undefined },
    'hidden and nonexistent operations have indistinguishable typed problems',
  );
  assert.equal(hiddenProblem.code, 'PC-AUTH-0005');
  assert.equal(hiddenProblem.truthState, 'DENIED');
  assert.ok(
    !(await hidden.text()).includes(operation.resourceRef),
    'operation resource does not leak',
  );
  const replay = await create(privacyDomainId);
  assert.equal(replay.status, 202, await replay.clone().text());
  assert.deepEqual(await replay.json(), operation);
  const cross = await create(otherPrivacy, selectedSession);
  assert.equal(cross.status, 412, await cross.clone().text());
  assert.ok(
    !(await cross.text()).includes(operation.operationId),
    'another domain cannot replay the operation',
  );
  const records = await admin.query(
    `select privacy_domain_id::text privacy from control.idempotency_record
    where participant_id=$1 and principal_id=$2 and idempotency_key=$3`,
    [participantId, principal, key],
  );
  assert.deepEqual(
    records.rows,
    [{ privacy: privacyDomainId }],
    'cross-domain failed command reserved no operation',
  );
  assert.equal((await read(privacyDomainId)).status, 200, 'original context remains readable');
  process.stdout.write(
    'OPENPC_OPERATION_PRIVACY|PASS|public-read|scope-denial|authorized-hidden|same-domain-replay|cross-domain-replay-denied\n',
  );
}

try {
  await privacyReadbackAndReplay();
  for (const ordering of ['commit-first', 'revocation-first']) {
    const session = await login();
    const body = await freshApprovalCandidate(session, ordering);
    const key = `authority-fence-${ordering}-${uuid()}`;
    const authorization = barrier();
    const commit = barrier();
    const instrumentedPool = new Proxy(runtime, {
      get(target, property) {
        if (property !== 'connect') {
          const value = Reflect.get(target, property);
          return typeof value === 'function' ? value.bind(target) : value;
        }
        return async () => {
          const client = await target.connect();
          return new Proxy(client, {
            get(connection, property) {
              if (property === 'query')
                return async (...args) => {
                  // Scheduling only: every authority query, state write, and commit is real SQL.
                  if (args[0] === 'commit' && ordering === 'commit-first') {
                    const { rows } = await connection.query('select pg_backend_pid() pid');
                    await commit.wait(rows[0].pid);
                  }
                  return connection.query(...args);
                };
              const value = Reflect.get(connection, property);
              return typeof value === 'function' ? value.bind(connection) : value;
            },
          });
        };
      },
    });
    const app = buildPolicyService({
      pool: instrumentedPool,
      internalToken: await secret('policy_internal_token'),
      trustedArtifactSigners: [],
      identityGateway: {
        async authorize(input) {
          const actor = await gateway.authorize(input);
          if (ordering === 'revocation-first') await authorization.wait();
          return actor;
        },
      },
    });
    let creation;
    let revocation;
    try {
      const revoke = await logoutRequest(session, `${key}-logout`);
      creation = app
        .inject({
          method: 'POST',
          url: '/api/v1/approval-requests',
          headers: {
            ...headers(session, key),
            'x-csrf-token': await csrf(session, body.actionIntentId),
            'x-openpc-action-intent-digest': body.actionIntentDigest,
          },
          payload: body,
        })
        .then((response) => response);
      if (ordering === 'commit-first') {
        const pid = await bounded(commit.arrived, 'business commit barrier');
        revocation = revoke();
        await waitForBlockedSession(pid);
        commit.release();
      } else {
        await bounded(authorization.arrived, 'real authorization completed');
        revocation = revoke();
        const response = await revocation;
        assert.equal(response.status, 202, await response.text());
        authorization.release();
      }
      const [created, revoked] = await bounded(Promise.all([creation, revocation]), ordering);
      assert.equal(revoked.status, 202, 'supported session revocation committed');
      assert.equal(created.statusCode, ordering === 'commit-first' ? 202 : 403, created.body);
      const effect = (
        await admin.query(
          `select (select count(*)::int from control.idempotency_record where participant_id=$1
          and idempotency_key=$2 and terminal_state='COMMITTED') operations,
          (select count(*)::int from control.approval_request where participant_id=$1
            and maker_authority->>'sessionId'=$3) approvals,
          (select state from control.session where participant_id=$1 and session_id=$3::uuid) session`,
          [participantId, key, session.split('.')[1]],
        )
      ).rows[0];
      const count = ordering === 'commit-first' ? 1 : 0;
      assert.deepEqual(
        effect,
        { operations: count, approvals: count, session: 'REVOKED' },
        ordering,
      );
      if (ordering === 'commit-first') {
        const resource = created.json().resourceRef;
        const readback = await fetch(`${origin}/api/v1/approval-requests/${resource}`, {
          headers: headers(readSession, `${key}-read`),
          signal: AbortSignal.timeout(15_000),
        });
        assert.equal(readback.status, 200);
        assert.equal((await readback.json()).state, 'REQUESTED');
      }
    } finally {
      commit.release();
      authorization.release();
      await Promise.allSettled([creation, revocation]);
      await app.close();
    }
  }
  process.stdout.write(
    'OPENPC_AUTHORITY_FENCE_RACE PASS commit-first waits revocation-first denies public-logout durable-readback forbidden-effects\n',
  );
} finally {
  await runtime.end();
  await admin.end();
}
