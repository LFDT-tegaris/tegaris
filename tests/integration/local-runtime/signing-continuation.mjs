import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { request } from 'node:https';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { Client } from 'pg';
import { createSigningContinuationVerifier } from '../../../services/identity-service/src/domain/signing-continuation.ts';
import { loadSigningContinuationContext } from '../../../services/identity-service/src/db/signing-continuation-context.ts';

// Runs only after supported ADVANCE/RECOVER owners produced the durable original provider observation.
const [secretRoot, participantId, privacyDomainId, rotationRef, operationId, attemptId] =
  process.argv.slice(2);
const read = (name) => readFile(join(secretRoot, name));
const ca = await read('identity_mtls_ca.pem');
const api = { cert: await read('business_api_cert.pem'), key: await read('business_api_key.pem') };
const worker = {
  cert: await read('business_worker_cert.pem'),
  key: await read('business_worker_key.pem'),
};
const payload = {
  privacyDomainId,
  rotationId: rotationRef.split(':').at(-1),
  operationId,
  attemptId,
};
function exchange(body, identity = api) {
  return new Promise((resolve, reject) => {
    const req = request(
      'https://127.0.0.1:53444/internal/v1/signing-rotation-attempts/reconcile-assertion',
      {
        method: 'POST',
        ca,
        ...identity,
        minVersion: 'TLSv1.3',
        maxVersion: 'TLSv1.3',
        rejectUnauthorized: true,
        headers: { 'Content-Type': 'application/json' },
        timeout: 5000,
      },
      (res) => {
        const chunks = [];
        let size = 0;
        res.on('data', (chunk) => {
          size += chunk.length;
          if (size > 20000) res.destroy(new Error('Bounded issuer response exceeded'));
          else chunks.push(chunk);
        });
        res.on('error', reject);
        res.on('end', () =>
          resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(chunks).toString()) }),
        );
      },
    );
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('Issuer timeout')));
    req.end(JSON.stringify(body));
  });
}
const client = new Client({
  host: '127.0.0.1',
  port: 55432,
  database: 'openpc_control',
  user: 'openpc_configuration_runtime',
  password: (await read('control_api_runtime_db_password.txt')).toString().trim(),
});
const begin = async () => {
  await client.query('begin');
  await client.query(
    "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1',true)",
    [participantId, privacyDomainId, operationId],
  );
};
try {
  await client.connect();
  await assert.rejects(exchange(payload, {}), 'no client certificate cannot reach issuer');
  assert.equal(
    (await exchange(payload, worker)).status,
    403,
    'worker certificate cannot impersonate API workload',
  );
  assert.equal(
    (await exchange({ ...payload, privacyDomainId: '018f0000-0000-7000-8000-000000000202' }))
      .status,
    403,
  );
  assert.equal(
    (await exchange({ ...payload, attemptId: '018f0000-0000-7000-8000-000000000999' })).status,
    403,
  );
  assert.equal((await exchange({ ...payload, dispatch: true })).status, 403);
  await begin();
  const peer = (
    await client.query(
      `select c.principal_id::text as "principalId",c.credential_id::text as "credentialId",
  c.credential_epoch::text as "credentialEpoch",c.public_key_digest as "publicKeyDigest" from control.credential c
  join control.signing_key_rotation r on r.participant_id=c.participant_id and r.workload_credential_id=c.credential_id
  where r.participant_id=$1 and r.privacy_domain_id=$2 and r.rotation_id=$3`,
      [participantId, privacyDomainId, payload.rotationId],
    )
  ).rows[0];
  const expected = await loadSigningContinuationContext(
    client,
    { ...peer, participantId, privacyDomainId },
    payload.rotationId,
    operationId,
    attemptId,
  );
  await client.query('commit');
  const issued = await exchange(payload);
  assert.equal(issued.status, 200, 'identity issues only the bound recorded effect');
  const verify = createSigningContinuationVerifier([
    await read('identity_continuation_public_key.der'),
  ]);
  const verified = await verify(issued.body.assertion, expected, new Date());
  assert.equal(verified.context.effect, 'FINALIZE_EXISTING_SIGNING_ROTATION_ATTEMPT');
  assert.equal(verified.context.targetState, 'PREPARED');
  assert.equal(verified.context.rotationRevision, '3');
  assert.equal(verified.context.currentAuthorityStatus, 'UNCHANGED_LIVE');
  await assert.rejects(
    verify(issued.body.assertion, expected, new Date(Number(verified.expiresAtNs / 1_000_000n))),
    'expired capability cannot finalize',
  );
  for (const changed of [
    { privacyDomainId: '018f0000-0000-7000-8000-000000000202' },
    { providerAttemptId: '018f0000-0000-7000-8000-000000000999' },
    { rotationRevision: '4' },
    { currentAuthorityStatus: 'CHANGED' },
  ])
    await assert.rejects(verify(issued.body.assertion, { ...expected, ...changed }, new Date()));
  assert.equal(
    (await exchange(payload)).status,
    403,
    'a second issuer request cannot mint another live JTI',
  );
  await begin();
  const stored = (
    await client.query(
      `select assertion_digest,context_digest,context_preimage,state from control.signing_continuation
  where participant_id=$1 and privacy_domain_id=$2 and assertion_id=$3`,
      [participantId, privacyDomainId, verified.assertionId],
    )
  ).rows[0];
  assert.equal(stored.state, 'ISSUED');
  assert.deepEqual(
    stored.assertion_digest,
    createHash('sha256').update(issued.body.assertion).digest(),
  );
  assert.deepEqual(JSON.parse(stored.context_preimage.toString()), expected);
  assert.deepEqual(
    stored.context_digest,
    createHash('sha256').update(stored.context_preimage).digest(),
  );
  await assert.rejects(
    client.query(
      `insert into control.signing_continuation select * from control.signing_continuation
  where assertion_id=$1`,
      [verified.assertionId],
    ),
    (error) => error.code === '42501',
    'API cannot issue continuation records',
  );
  await client.query('rollback');
  process.stdout.write(
    'OPENPC_SIGNING_CONTINUATION_ISSUER|PASS|real-api-mtls|wrong-workload-denied|cross-scope-denied|exact-recorded-effect|pinned-jwt|one-live-jti|no-bearer-storage|api-cannot-issue\n',
  );
} finally {
  await client.query('rollback').catch(() => {});
  await client.end();
}
