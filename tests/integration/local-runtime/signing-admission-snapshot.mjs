import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { setTimeout as pause } from 'node:timers/promises';
import { Client } from 'pg';
import { BusinessSigningTrustError } from '../../../packages/security-kernel/src/business-transition/signing-trust.ts';
import {
  discoverBusinessSigningKey,
  fenceBusinessSigningKey,
} from '../../../services/identity-service/src/db/business-signing-store.ts';

// No business states are seeded: the public ADVANCE has reserved the real provider attempt,
// and the runner has paused its worker solely to make the serializable snapshot ordering exact.
const [secretRoot, participantId, privacyDomainId, rotationRef, operationId, workerId] =
  process.argv.slice(2);
const options = {
  host: '127.0.0.1',
  port: 55432,
  database: 'openpc_control',
  user: 'openpc_configuration_runtime',
  password: (
    await readFile(join(secretRoot, 'control_api_runtime_db_password.txt'), 'utf8')
  ).trim(),
  statement_timeout: 15000,
};
const stale = new Client(options),
  current = new Client(options);
const context = (client) =>
  client.query(
    "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-INDEXER_PROFILES_CREATE_RESOURCE-V1',true)",
    [participantId, privacyDomainId, operationId],
  );
const selection = `select profile_digest,admission_version::text from control.business_signing_selection
 where participant_id=$1 and privacy_domain_id=$2 and signer_id=(select old_signer_id from control.signing_key_rotation
 where participant_id=$1 and privacy_domain_id=$2 and rotation_id=$3) order by profile_digest`;
const values = [participantId, privacyDomainId, rotationRef.split(':').at(-1)];
try {
  await stale.connect();
  await current.connect();
  // Boundary probes roll back every change to real retained authority; they create no business state.
  await current.query('begin');
  await context(current);
  const retained = (
    await current.query(
      `select a.attempt_id,convert_from(c.authorization_snapshot,'UTF8')::jsonb as snapshot
    from control.signing_provider_attempt a join control.signing_rotation_command c using(participant_id,privacy_domain_id,operation_id)
    where c.participant_id=$1 and c.privacy_domain_id=$2 and c.operation_id=$3 and a.state='READY' and a.request->>'method'='PREPARE'`,
      [participantId, privacyDomainId, operationId],
    )
  ).rows[0];
  assert.ok(retained);
  const authorityStatus = async () =>
    (
      await current.query('select openpc.signing_attempt_authority_status($1) as status', [
        retained.attempt_id,
      ])
    ).rows[0].status;
  assert.equal((await authorityStatus()).unchangedLive, true);
  for (const authority of retained.snapshot.authorities) {
    await current.query('savepoint changed_authority');
    await current.query(
      "update control.session set issued_at=issued_at-interval '1 hour',last_seen_at=last_seen_at-interval '1 hour',idle_expires_at=idle_expires_at-interval '1 hour',absolute_expires_at=absolute_expires_at-interval '1 hour',step_up_verified_at=step_up_verified_at-interval '1 hour' where participant_id=$1 and session_id=$2",
      [participantId, authority.sessionId],
    );
    assert.equal(
      (await authorityStatus()).unchangedLive,
      false,
      'expired caller/maker/checker cannot authorize a new dispatch',
    );
    await current.query('rollback to savepoint changed_authority');
    await current.query(
      "update control.session set state='REVOKED',revoked_at=clock_timestamp(),revoked_reason='bounded rollback probe' where participant_id=$1 and session_id=$2",
      [participantId, authority.sessionId],
    );
    assert.equal(
      (await authorityStatus()).unchangedLive,
      false,
      'revoked caller/maker/checker cannot authorize a new dispatch',
    );
    await current.query('rollback to savepoint changed_authority');
  }
  await current.query('savepoint fabricated_dispatch');
  await assert.rejects(
    current.query(
      'update control.signing_provider_attempt set dispatched_at_ns=1 where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3',
      [participantId, privacyDomainId, retained.attempt_id],
    ),
    /DATA-6020-ATTEMPT-DISPATCH-TIME/,
    'callers cannot fabricate dispatch time',
  );
  await current.query('rollback to savepoint fabricated_dispatch');
  await current.query('savepoint credential_usage');
  const credentials = (await authorityStatus()).dependencies.credential;
  for (const credential of credentials) {
    await current.query(
      'update control.credential set row_version=row_version+1 where credential_id=$1',
      [credential.credential_id],
    );
  }
  assert.equal(
    (await authorityStatus()).unchangedLive,
    true,
    'credential usage counters do not change the bound authority',
  );
  if (credentials.length) {
    await current.query("update control.credential set state='REVOKED' where credential_id=$1", [
      credentials[0].credential_id,
    ]);
    assert.equal(
      (await authorityStatus()).unchangedLive,
      false,
      'credential revocation still closes dispatch',
    );
  }
  await current.query('rollback to savepoint credential_usage');
  assert.equal((await authorityStatus()).unchangedLive, true);
  await current.query('rollback');
  process.stdout.write(
    'OPENPC_SIGNING_DISPATCH_AUTHORITY|PASS|caller-maker-checker-expiry-and-revocation-denied|fabricated-dispatch-time-denied|rolled-back-boundary-probes\n',
  );
  await stale.query('begin isolation level serializable');
  await context(stale);
  const before = await stale.query(selection, values);
  assert.equal(before.rowCount, 2, 'the role has two real profile selections');
  await current.query('begin');
  await context(current);
  const profile = (
    await current.query(
      `select p.profile_id as "profileId",p.profile_version::integer as "profileVersion",
   p.profile_digest as "profileDigest",p.action_intent_id as "actionIntentId",p.catalog_operation_id as "catalogOperationId",
   r.environment_id as "environmentId" from control.business_transition_profile p cross join control.signing_key_rotation r
   where p.profile_digest=$1 and r.participant_id=$2 and r.privacy_domain_id=$3 and r.rotation_id=$4`,
      [before.rows[0].profile_digest, ...values],
    )
  ).rows[0];
  const signingScope = { ...profile, participantId, privacyDomainId };
  const discovery = await discoverBusinessSigningKey(current, signingScope);
  await current.query('commit');
  await promisify(execFile)('docker', ['start', workerId]);
  let fenced = false;
  for (let n = 0; n < 100; n++) {
    await current.query('begin');
    await context(current);
    const command = await current.query(
      'select state from control.signing_rotation_command where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3',
      [participantId, privacyDomainId, operationId],
    );
    if (command.rows[0]?.state === 'WRITE_AMBIGUITY') {
      const after = await current.query(selection, values);
      assert.deepEqual(
        after.rows.map((r) => BigInt(r.admission_version)),
        before.rows.map((r) => BigInt(r.admission_version) + 1n),
      );
      fenced = true;
    }
    await current.query('commit');
    if (fenced) break;
    await pause(100);
  }
  assert.ok(fenced, 'the worker durably recorded real lost-response ambiguity');
  await assert.rejects(
    stale.query(selection + ' for share', values),
    (error) => error.code === '40001',
    'an old serializable snapshot cannot pass the new admission fence',
  );
  await current.query('begin');
  await context(current);
  await assert.rejects(
    fenceBusinessSigningKey(current, signingScope, discovery),
    (error) => error instanceof BusinessSigningTrustError,
    'an old discovery cannot authorize signing after the admission capability changed',
  );
  await current.query('rollback');
  process.stdout.write(
    'OPENPC_SIGNING_ADMISSION_SNAPSHOT|PASS|real-provider-ambiguity|stale-serializable-writer-aborted|stale-discovery-rejected\n',
  );
} finally {
  await stale.query('rollback').catch(() => {});
  await current.query('rollback').catch(() => {});
  await stale.end();
  await current.end();
}
