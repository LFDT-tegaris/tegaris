import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFile, readdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { Pool } from 'pg';

import { localOperationId } from '../../../services/identity-service/src/domain/local-operation-id.ts';
import { createLocalIdentityRuntimeVerifier } from '../../../services/identity-service/src/domain/identity-runtime-crypto.ts';
import { verifyIdentityRuntimeAuthorizationAssertion } from '../../../services/identity-service/src/domain/identity-runtime-authorization.ts';

const [
  secretRoot,
  participantId,
  privacyDomainId,
  sessionToken,
  operationPath,
  bodyText,
  providerContainer,
] = process.argv.slice(2);
const operation = JSON.parse(await readFile(operationPath, 'utf8'));
const body = JSON.parse(bodyText);
const origin = 'http://127.0.0.1:8080';
const pool = new Pool({
  host: '127.0.0.1',
  port: 55432,
  database: 'openpc_control',
  user: 'openpc_control',
  password: (await readFile(join(secretRoot, 'control_pg_password.txt'), 'utf8')).trim(),
  max: 1,
});
const headers = () => ({
  'cookie': `__Host-openpc_session=${sessionToken}`,
  'OpenPC-API-Version': '1',
  'OpenPC-Participant-ID': `urn:openpc:participant:${participantId}`,
  'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacyDomainId}`,
  'X-Request-ID': localOperationId(),
  'X-Correlation-ID': localOperationId(),
});
async function publicGet(path) {
  const response = await fetch(`${origin}${path}`, {
    headers: headers(),
    signal: AbortSignal.timeout(15000),
  });
  assert.equal(response.status, 200, 'authorized public read');
  return response.json();
}
async function records() {
  return (
    await pool.query(
      `select
    (select count(*)::int from control.indexer_profile where participant_id=$1) resources,
    (select count(*)::int from control.idempotency_record where participant_id=$1 and action_intent_id=$2) idempotency,
    (select count(*)::int from control.mutation_evidence where participant_id=$1 and action_intent_id=$2) evidence,
    (select count(*)::int from control.outbox_event where participant_id=$1 and aggregate_id=$3) events,
    (select count(*)::int from control.approval_request where participant_id=$1 and action_intent_id=$2) approvals,
    (select count(*)::int from control.mutation_candidate where participant_id=$1 and action_intent_id=$2) candidates,
    (select count(*)::int from control.audit_occurrence where participant_id=$1) receipts,
    (select count(*)::int from control.receipt_signing_attempt where participant_id=$1) signing_attempts,
    (select coalesce(sum(last_sequence),0)::text from control.business_outbox_head where participant_id=$1) business_sequences`,
      [participantId, body.actionIntentId, operation.resourceRef.split(':').at(-1)],
    )
  ).rows[0];
}
try {
  const before = await records();
  assert.equal(before.approvals, 0, 'ordinary action has no seeded or real approval');
  assert.equal(before.candidates, 0, 'ordinary action does not stage an approval candidate');
  assert.equal(before.idempotency, 1);
  assert.equal(before.evidence, 1);
  assert.equal(before.events, 1);
  const evidence = (
    await pool.query(
      `select e.*,s.issued_at,s.idle_expires_at,s.absolute_expires_at,
      s.session_epoch::text,s.delegation_epoch::text,a.row_version::text assignment_epoch
    from control.mutation_evidence e join control.session s
      on s.participant_id=e.participant_id and s.session_id=$2
    join control.assignment a on a.participant_id=e.participant_id and a.assignment_id=e.bound_assignment_id
    where e.participant_id=$1 and e.operation_id=$3`,
      [participantId, sessionToken.split('.')[1], operation.operationId],
    )
  ).rows[0];
  assert.ok(evidence, 'durable authentication input exists');
  assert.equal(evidence.approval_request_id, null);
  assert.equal(evidence.mfa_challenge_id, null);
  assert.equal(evidence.checker_principal_id, null);
  assert.equal(evidence.webauthn_assertion_binding_digest, null);
  assert.deepEqual(
    createHash('sha256').update(evidence.evidence_cbor).digest(),
    evidence.evidence_digest,
  );
  const verifier = createLocalIdentityRuntimeVerifier([
    await readFile(join(secretRoot, 'identity_runtime_signing_public_key.der')),
  ]);
  assert.ok(await verifier.verifyCanonicalAssertion(evidence.evidence_cbor, evidence.cose_sign1));
  const context = {
    participantId,
    principalId: evidence.principal_id,
    sessionId: sessionToken.split('.')[1],
    sessionEpoch: evidence.session_epoch,
    sessionIssuedAt: evidence.issued_at,
    sessionIdleExpiresAt: evidence.idle_expires_at,
    sessionAbsoluteExpiresAt: evidence.absolute_expires_at,
    participantEpoch: String(evidence.bound_participant_epoch),
    principalEpoch: String(evidence.bound_principal_epoch),
    assignmentId: evidence.bound_assignment_id,
    assignmentRowVersion: evidence.assignment_epoch,
    authorityEnvelopeId: evidence.bound_authority_envelope_id,
    authorityEpoch: String(evidence.bound_envelope_epoch),
    delegationEpoch: evidence.delegation_epoch,
    actionIntentId: body.actionIntentId,
    catalogOperationId: 'CFG-OP-CREATE-INDEXER-PROFILE',
    resourceId: operation.resourceRef.split(':').at(-1),
    candidateDigest: `sha256:${evidence.candidate_digest.toString('hex')}`,
    sessionToken,
    configurationBinding: {
      privacyDomainId,
      actionIntentDigest: body.actionIntentDigest,
      expectedRevision: '0',
    },
  };
  assert.ok(
    verifyIdentityRuntimeAuthorizationAssertion(evidence.evidence_cbor, context, new Date()),
  );
  assert.equal(
    verifyIdentityRuntimeAuthorizationAssertion(
      evidence.evidence_cbor,
      {
        ...context,
        configurationBinding: { ...context.configurationBinding, expectedRevision: '1' },
      },
      new Date(),
    ),
    undefined,
  );
  assert.equal(
    verifyIdentityRuntimeAuthorizationAssertion(
      evidence.evidence_cbor,
      { ...context, candidateDigest: `sha256:${'ff'.repeat(32)}` },
      new Date(),
    ),
    undefined,
  );
  const csrfResponse = await fetch(`${origin}/api/v1/session/csrf`, {
    method: 'POST',
    headers: { ...headers(), origin, 'content-type': 'application/json' },
    body: JSON.stringify({ actionIntentId: body.actionIntentId }),
    signal: AbortSignal.timeout(15000),
  });
  assert.equal(csrfResponse.status, 200);
  const csrf = (await csrfResponse.json()).csrfToken;
  const mutationHeaders = {
    ...headers(),
    origin,
    'content-type': 'application/json',
    'X-CSRF-Token': csrf,
    'Idempotency-Key': operation.idempotencyKey,
    'OpenPC-Action-Intent-Digest': body.actionIntentDigest,
  };
  const changed = await fetch(`${origin}/api/v1/indexer-profiles`, {
    method: 'POST',
    headers: mutationHeaders,
    body: JSON.stringify({ ...body, engineVersion: '9.9.9' }),
    signal: AbortSignal.timeout(15000),
  });
  assert.equal(changed.status, 412, 'same key with changed body is stale and has no effect');
  const wrongPrivacy = await fetch(`${origin}/api/v1/indexer-profiles`, {
    method: 'POST',
    headers: {
      ...mutationHeaders,
      'Idempotency-Key': `denied-${localOperationId()}`,
      'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${localOperationId()}`,
    },
    body: bodyText,
    signal: AbortSignal.timeout(15000),
  });
  assert.equal(wrongPrivacy.status, 403, 'ungranted privacy is denied');
  assert.deepEqual(
    await records(),
    before,
    'denials leave resource, idempotency, proof, event and approval stores unchanged',
  );
  const readOperation = await publicGet(`/api/v1/operations/${operation.operationId}`);
  assert.equal(readOperation.operationId, operation.operationId);
  assert.equal(readOperation.state, 'SUCCEEDED');
  const resource = await publicGet(`/api/v1/indexer-profiles/${operation.resourceRef}`);
  assert.equal(resource.engineVersion, body.engineVersion);
  assert.equal(resource.revision, '1');
  // Exercise the actual UPDATE owner on an independently created resource. The
  // first indexer remains the downstream qualification journey's owned input.
  const createKey = `state-${localOperationId()}`;
  const createBody = JSON.stringify({
    ...body,
    reason: 'Exercise durable indexer update state.',
    engineVersion: '2.0.0',
  });
  assert.match(providerContainer, /^[0-9a-f]{64}$/u);
  const ownedProject = execFileSync(
    'docker',
    [
      'inspect',
      '--format',
      '{{index .Config.Labels "com.docker.compose.project"}}',
      providerContainer,
    ],
    { encoding: 'utf8' },
  ).trim();
  assert.match(ownedProject, /^openpc-local-e2e-[0-9a-f]{12}$/u);
  execFileSync('docker', ['stop', providerContainer], { stdio: 'ignore' });
  try {
    const unavailable = await fetch(`${origin}/api/v1/indexer-profiles`, {
      method: 'POST',
      headers: { ...mutationHeaders, 'Idempotency-Key': createKey },
      body: createBody,
      signal: AbortSignal.timeout(15000),
    });
    assert.equal(unavailable.status, 503, 'unavailable signing provider cannot commit');
    assert.equal((await unavailable.json()).code, 'PC-INTEGRATION-5001');
    assert.deepEqual(
      await records(),
      before,
      'provider failure rolls back domain state, reservation, receipt and sequence',
    );
    const offlineReplay = await fetch(`${origin}/api/v1/indexer-profiles`, {
      method: 'POST',
      headers: mutationHeaders,
      body: bodyText,
      signal: AbortSignal.timeout(15000),
    });
    assert.equal(
      offlineReplay.status,
      202,
      'committed replay does not require a new provider signature',
    );
    assert.deepEqual(await offlineReplay.json(), operation);
  } finally {
    execFileSync('docker', ['start', providerContainer], { stdio: 'ignore' });
  }
  for (let attempt = 0; ; attempt += 1) {
    const health = execFileSync(
      'docker',
      ['inspect', '--format', '{{.State.Health.Status}}', providerContainer],
      { encoding: 'utf8' },
    ).trim();
    if (health === 'healthy') break;
    assert.ok(attempt < 50, 'owned signing provider restarts');
    await delay(200);
  }
  const providerRoot = join(secretRoot, '..', 'data', 'signing-provider');
  const priorAttempts = new Set(await readdir(join(providerRoot, 'attempts')));
  await writeFile(
    join(providerRoot, 'faults', 'next-SIGN_RECEIPT.json'),
    JSON.stringify({ mode: 'DROP_AFTER_EFFECT' }),
    { flag: 'wx', mode: 0o600 },
  );
  const lostSignature = await fetch(`${origin}/api/v1/indexer-profiles`, {
    method: 'POST',
    headers: { ...mutationHeaders, 'Idempotency-Key': createKey },
    body: createBody,
    signal: AbortSignal.timeout(15000),
  });
  assert.equal(
    lostSignature.status,
    503,
    'lost provider signature response cannot establish a local effect',
  );
  assert.deepEqual(
    await records(),
    before,
    'an orphan signature rolls back its attempt, aggregate, evidence and sequence',
  );
  const orphanNames = (await readdir(join(providerRoot, 'attempts'))).filter(
    (name) => !priorAttempts.has(name),
  );
  assert.equal(orphanNames.length, 1, 'exactly one external signing attempt occurred');
  const orphan = JSON.parse(await readFile(join(providerRoot, 'attempts', orphanNames[0]), 'utf8'));
  assert.equal(orphan.request.method, 'SIGN_RECEIPT');
  assert.equal(
    orphan.observation.outcome,
    'SUCCEEDED',
    'provider retained a real signature before dropping its response',
  );
  assert.equal(
    (
      await pool.query(
        'select count(*)::integer count from control.receipt_signing_attempt where attempt_id=$1',
        [orphan.request.attemptId],
      )
    ).rows[0].count,
    0,
  );
  const create = await fetch(`${origin}/api/v1/indexer-profiles`, {
    method: 'POST',
    headers: { ...mutationHeaders, 'Idempotency-Key': createKey },
    body: createBody,
    signal: AbortSignal.timeout(15000),
  });
  assert.equal(create.status, 202, 'independent indexer created through its public owner');
  process.stdout.write(
    'OPENPC_EXTERNAL_SIGNING_PROVIDER|PASS|mtls-signature|outage-rollback|offline-replay|restart-same-key\n',
  );
  const created = await create.json();
  assert.notEqual(
    created.operationId,
    orphan.request.operationId,
    'retry recomputes a fresh transaction after definite local rollback',
  );
  const updateAction = 'ACT-INDEXER_PROFILES_UPDATE_RESOURCE-V1';
  const updateDigest = (
    await pool.query(
      `select 'sha256:'||encode(semantic_digest,'hex') digest from control.action_intent where action_intent_id=$1`,
      [updateAction],
    )
  ).rows[0].digest;
  const updateCsrfResponse = await fetch(`${origin}/api/v1/session/csrf`, {
    method: 'POST',
    headers: { ...headers(), origin, 'content-type': 'application/json' },
    body: JSON.stringify({ actionIntentId: updateAction }),
    signal: AbortSignal.timeout(15000),
  });
  assert.equal(updateCsrfResponse.status, 200);
  const updateCsrf = (await updateCsrfResponse.json()).csrfToken;
  const updateBody = {
    actionIntentId: updateAction,
    actionIntentDigest: updateDigest,
    expectedRevision: '1',
    replacementDigest: `sha256:${'71'.repeat(32)}`,
    reason: 'Replace actual indexer method profile.',
  };
  const updateKey = `update-${localOperationId()}`;
  const target = `${origin}/api/v1/indexer-profiles/${created.resourceRef}`;
  const initialRead = await fetch(target, {
    headers: headers(),
    signal: AbortSignal.timeout(15000),
  });
  assert.equal(initialRead.status, 200);
  const updateHeaders = {
    ...mutationHeaders,
    'X-CSRF-Token': updateCsrf,
    'OpenPC-Action-Intent-Digest': updateDigest,
    'Idempotency-Key': updateKey,
    'If-Match': initialRead.headers.get('etag'),
  };
  const update = await fetch(target, {
    method: 'PATCH',
    headers: updateHeaders,
    body: JSON.stringify(updateBody),
    signal: AbortSignal.timeout(15000),
  });
  assert.equal(update.status, 202, 'real business change commits');
  const updatedOperation = await update.json();
  const replay = await fetch(target, {
    method: 'PATCH',
    headers: updateHeaders,
    body: JSON.stringify(updateBody),
    signal: AbortSignal.timeout(15000),
  });
  assert.equal(replay.status, 202);
  assert.deepEqual(await replay.json(), updatedOperation);
  const updatedRead = await fetch(target, {
    headers: headers(),
    signal: AbortSignal.timeout(15000),
  });
  assert.equal(updatedRead.status, 200);
  const updated = await updatedRead.json();
  assert.equal(updated.revision, '2');
  assert.equal(updated.methodProfileDigest, updateBody.replacementDigest);
  const effects = async () =>
    (
      await pool.query(
        `select
    (select count(*)::int from control.idempotency_record where participant_id=$1 and action_intent_id=$2) idempotency,
    (select count(*)::int from control.mutation_evidence where participant_id=$1 and action_intent_id=$2) evidence,
    (select count(*)::int from control.outbox_event where participant_id=$1 and aggregate_id=$3) events,
    (select revision::text from control.indexer_profile where participant_id=$1 and indexer_profile_id=$3) revision`,
        [participantId, updateAction, created.resourceRef.split(':').at(-1)],
      )
    ).rows[0];
  const committedEffects = await effects();
  assert.deepEqual(committedEffects, { idempotency: 1, evidence: 1, events: 2, revision: '2' });
  const noop = await fetch(target, {
    method: 'PATCH',
    headers: {
      ...updateHeaders,
      'Idempotency-Key': `noop-${localOperationId()}`,
      'If-Match': updatedRead.headers.get('etag'),
    },
    body: JSON.stringify({ ...updateBody, expectedRevision: '2' }),
    signal: AbortSignal.timeout(15000),
  });
  assert.equal(noop.status, 412, 'revision-only update is rejected');
  assert.deepEqual(
    await effects(),
    committedEffects,
    'rejected no-op rolls back the row, reservation, evidence and event',
  );
  process.stdout.write(
    'OPENPC_ORDINARY_CONFIGURATION_AUTHORIZATION|PASS|public-session|no-seeded-approval|public-key-verification|scope-and-candidate-binding|create-update-replay|noop-rollback|denial-no-effects|durable-readback\n',
  );
} finally {
  await pool.end();
}
