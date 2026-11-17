import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { createRequire } from 'node:module';
import { createHash } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
const { Pool } = createRequire(join(process.cwd(), 'package.json'))('pg');
const { uuidv7 } = await import(
  join(process.cwd(), 'services/control-api/src/configuration/governed-mutation-http.ts')
);
const phase = process.argv[3];
assert.ok(['connected', 'disconnected', 'reconnected'].includes(phase));
const root = process.argv[2];
assert.ok(root?.startsWith('/'));
const evidence = join(root, 'evidence/runtime-bootstrap'),
  secrets = join(root, 'secrets');
const input = JSON.parse(await readFile(join(evidence, 'discovery-credential-input.json'), 'utf8'));
const actors = JSON.parse(await readFile(join(evidence, 'deployment-intent-actors.json'), 'utf8'));
const pool = new Pool({
  host: '127.0.0.1',
  port: 55432,
  database: 'openpc_control',
  user: 'openpc_control',
  password: (await readFile(join(secrets, 'control_pg_password.txt'), 'utf8')).trim(),
  max: 1,
});
try {
  const wanted = phase === 'disconnected' ? 'OFFLINE' : 'DISCOVERED';
  let view;
  for (let attempt = 0; attempt < 60; attempt++) {
    const response = await fetch(
      `http://127.0.0.1:8080/api/v1/runtime-targets/urn:openpc:resource:${input.targetId}`,
      {
        headers: {
          'Cookie': `__Host-openpc_session=${actors.maker.sessionToken}`,
          'OpenPC-API-Version': '1',
          'OpenPC-Participant-ID': `urn:openpc:participant:${input.participantId}`,
          'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${input.privacyDomainId}`,
          'X-Request-ID': uuidv7(),
          'X-Correlation-ID': uuidv7(),
        },
      },
    );
    assert.equal(response.status, 200);
    view = await response.json();
    if (view.state === wanted) break;
    await delay(250);
  }
  assert.equal(view.state, wanted);
  for (const field of ['desiredGenerationDigest', 'activeGenerationDigest', 'xdsVersionDigest'])
    assert.equal(view[field], null);
  await pool.query('begin');
  await pool.query(
    "select openpc.set_request_context('PARTICIPANT',$1,$2,uuidv7(),'ACT-RUNTIME_CONFIGURATION_GENERATIONS_ACTIVATE_RESOURCE-V1',true)",
    [input.participantId, input.privacyDomainId],
  );
  const row = (
    await pool.query(
      `select c.connection_id::text,c.credential_id::text,c.certificate_digest,c.connected,
    c.credential_epoch::text,c.principal_epoch::text,
    c.observed_at<=clock_timestamp() and c.valid_until>clock_timestamp() and c.valid_until<=clock_timestamp()+interval '15 seconds' bounded_current,
    k.certificate_der,k.credential_epoch::text actual_credential_epoch,p.authority_epoch::text actual_principal_epoch,
    openpc.runtime_target_discovery_current(c.participant_id,c.privacy_domain_id,c.runtime_target_id) current
    from control.runtime_target_connection c join control.credential k using(participant_id,credential_id)
    join control.principal p on p.participant_id=k.participant_id and p.principal_id=k.principal_id
    where c.participant_id=$1 and c.privacy_domain_id=$2 and c.runtime_target_id=$3`,
      [input.participantId, input.privacyDomainId, input.targetId],
    )
  ).rows[0];
  assert.ok(row);
  assert.equal(row.credential_id, input.credentialId);
  assert.equal(
    row.certificate_digest,
    `sha256:${createHash('sha256').update(row.certificate_der).digest('hex')}`,
  );
  assert.equal(row.credential_epoch, row.actual_credential_epoch);
  assert.equal(row.principal_epoch, row.actual_principal_epoch);
  assert.equal(row.connected, phase !== 'disconnected');
  assert.equal(row.current, phase !== 'disconnected');
  if (phase !== 'disconnected') assert.equal(row.bounded_current, true);
  const checkpoint = join(evidence, 'discovery-first-connection.json');
  if (phase === 'connected')
    await writeFile(checkpoint, JSON.stringify({ connectionId: row.connection_id }), {
      mode: 0o600,
    });
  if (phase === 'reconnected')
    assert.notEqual(row.connection_id, JSON.parse(await readFile(checkpoint, 'utf8')).connectionId);
  for (const table of ['policy_generation', 'runtime_configuration_generation'])
    assert.equal(
      (
        await pool.query(
          `select count(*)::int n from control.${table} where participant_id=$1 and privacy_domain_id=$2`,
          [input.participantId, input.privacyDomainId],
        )
      ).rows[0].n,
      0,
    );
  process.stdout.write(
    `OPENPC_RUNTIME_DISCOVERY|PASS|${phase}|public-state=${wanted}|verified-certificate|current-epochs|bounded-lease|non-serving\n`,
  );
} finally {
  await pool.query('rollback').catch(() => {});
  await pool.end();
}
