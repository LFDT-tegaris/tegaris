import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { Pool } from 'pg';
import { uuidv7 } from '../../../services/control-api/src/configuration/governed-mutation-http.ts';
import { buildB5Harness, projectionFor } from '../../privacy/i07-gate2-b5-test-support.ts';
import { bindLocalContext } from '../../../services/control-api/src/privacy-explorer/context.ts';
import { PostgresExplorerCustody } from '../../../services/control-api/src/privacy-explorer/postgres-custody.ts';
import { ExplorerContinuationCustody } from '../../../services/control-api/src/privacy-explorer/continuation-custody.ts';
import { createPrivacyExplorerService } from '../../../services/control-api/src/privacy-explorer/service.ts';
import { redactProjection } from '../../../services/control-api/src/privacy-explorer/redaction.ts';
import { preauthorize } from '../../../services/control-api/src/privacy-explorer/preauthorization.ts';
import {
  narrowIntent,
  sha256CanonicalJson,
} from '../../../services/control-api/src/privacy-explorer/narrowing.ts';
import { createProjectionRequest } from '../../../services/control-api/src/privacy-explorer/request.ts';
import { postgresExplorerRouteAudit } from '../../../services/control-api/src/privacy-explorer/live-runtime.ts';

/** Downstream custody acceptance: deliberately not a public policy/login journey. */
export async function checkExplorerCustody(
  connection,
  participantId,
  privacyDomainId,
  principalId,
) {
  let pool = new Pool({ ...connection, user: 'openpc_configuration_runtime', max: 3 });
  const scope = {
    participantId,
    privacyDomainId,
    subject: `urn:openpc:principal:${principalId}`,
    actionIntentId: 'ACT-PRIVACY_EXPLORER_READ_PROJECTION-V1',
  };
  const key = randomBytes(32);
  const digest = `sha256:${'a'.repeat(64)}`;
  const generations = {
    queryDigest: digest,
    profileDigest: digest,
    authorityGeneration: digest,
    factGeneration: digest,
    identityGeneration: digest,
  };
  let contacts = 0;
  const harness = buildB5Harness({
    occurrenceId: randomUUID(),
    correlationId: randomUUID(),
    implementation: {
      readGovernedProjection: async (request, context) => {
        contacts += 1;
        const projection = projectionFor(request, context, 'PARTIAL');
        const { responseDigest: _, ...value } = projection;
        void _;
        value.page = { cursor: 'protected-source-continuation', gapFree: false };
        return { ...value, responseDigest: sha256CanonicalJson(value) };
      },
    },
  });
  const facts = {
    ...harness.input.context,
    participantId,
    privacyDomainId,
    subject: scope.subject,
  };
  const context = bindLocalContext(facts, {
    verify: (value) => (value === facts ? facts : undefined),
  });
  const input = { ...harness.input, context };
  const boundary = createProjectionRequest(
    narrowIntent(preauthorize(context, input.purposeAction), input.profile, input.query),
    input.seed,
  );
  const vault = new ExplorerContinuationCustody(key, scope, generations);
  const custody = new PostgresExplorerCustody(pool, scope);
  const redact = async (projection) => {
    const cursor = await custody.transaction((client) =>
      vault.retain(
        client,
        context.occurrenceId,
        projection.projection.page.cursor,
        new Date(Date.now() + 60_000).toISOString(),
      ),
    );
    return redactProjection(projection, {
      fieldsForRecord: () => ['PEF-A'],
      recordReference: (id) => vault.recordReference(id),
      cursor,
    });
  };
  try {
    const attempt = { phase: 'ADMISSION_REJECTED', attemptId: randomUUID() };
    const audit = postgresExplorerRouteAudit(pool);
    assert.deepEqual(await audit.append(attempt), {
      outcome: 'ACCEPTED',
      attemptId: attempt.attemptId,
      auditDigest: sha256CanonicalJson(attempt),
    });
    await assert.rejects(audit.append(attempt));
    assert.equal(
      (await pool.query('select * from control.privacy_explorer_route_audit')).rowCount,
      0,
    );
    // Even a zero-row statement must take the exclusive generation fence: row
    // locks alone cannot protect a disclosure from the first active generation.
    const writerPool = new Pool({ ...connection, user: 'postgres', max: 1 });
    const writer = new PostgresExplorerCustody(writerPool, scope);
    const mutate = () =>
      writer.transaction(async (client) => {
        await client.query("set local role openpc_control_worker; set local lock_timeout='100ms'");
        return client.query('update control.policy_generation set active=false where false');
      });
    try {
      await custody.transaction(async (client) => {
        await client.query('select pg_advisory_xact_lock_shared(hashtextextended($1,0))', [
          `openpc-policy-generations:${participantId}:${privacyDomainId}`,
        ]);
        await assert.rejects(mutate(), (error) => error.code === '55P03');
      });
      await mutate();
    } finally {
      await writerPool.end();
    }
    const service = createPrivacyExplorerService(harness.port, custody, redact);
    const result = await service.read(input);
    assert.equal(result.disposition, 'RELEASED');
    assert.equal(contacts, 1);
    assert.match(result.response.page.cursor, /^pec1\./);
    assert.match(result.response.records[0].id, /^per1\./);
    assert.deepEqual(
      result.response.records[0].fields.map((field) => field.fieldId),
      ['PEF-A'],
    );
    await custody.evidenceSink().append(result.evidence);
    const saved = await custody.transaction(
      async (client) =>
        (
          await client.query(
            `select snapshot,evidence,disposition,release_claim_id from control.privacy_explorer_execution
       where occurrence_id=$1`,
            [context.occurrenceId],
          )
        ).rows[0],
    );
    assert.equal(saved.disposition, 'OPEN');
    assert.equal(saved.release_claim_id, null);
    assert.equal(saved.snapshot.state, 'EVIDENCE_SEALED');
    assert.equal(saved.snapshot.rawState, 'DISPOSED');
    assert.equal(JSON.stringify(saved).includes('protected-source-continuation'), false);
    assert.equal(JSON.stringify(saved).includes('"records"'), false);
    const beforeClaim = await custody.transaction((client) =>
      client.query(
        'select sealed_cursor from control.privacy_explorer_continuation where occurrence_id=$1',
        [context.occurrenceId],
      ),
    );
    assert.equal(
      beforeClaim.rows[0].sealed_cursor.includes(Buffer.from('protected-source-continuation')),
      false,
    );
    await assert.rejects(
      custody.transaction((client) =>
        vault.consume(client, result.response.page.cursor, randomUUID()),
      ),
    );
    const claims = await Promise.allSettled(
      [0, 1].map(() =>
        custody.transaction((client) => custody.claim(client, boundary, result.evidence)),
      ),
    );
    assert.equal(claims.filter((claim) => claim.status === 'fulfilled').length, 1);
    assert.equal(claims.filter((claim) => claim.status === 'rejected').length, 1);
    await assert.rejects(
      custody.transaction((client) =>
        client.query(
          `update control.privacy_explorer_execution set disposition='OPEN',release_claim_id=null,
       release_authorized_at=null where occurrence_id=$1`,
          [context.occurrenceId],
        ),
      ),
    );
    const foreignVault = new ExplorerContinuationCustody(key, scope, {
      ...generations,
      identityGeneration: `sha256:${'b'.repeat(64)}`,
    });
    await assert.rejects(
      custody.transaction((client) =>
        foreignVault.consume(client, result.response.page.cursor, randomUUID()),
      ),
    );
    const consumption = await Promise.allSettled(
      [0, 1].map(() =>
        custody.transaction((client) =>
          vault.consume(client, result.response.page.cursor, randomUUID()),
        ),
      ),
    );
    assert.equal(consumption.filter((value) => value.status === 'fulfilled').length, 1);
    assert.equal(
      consumption.find((value) => value.status === 'fulfilled').value,
      'protected-source-continuation',
    );
    await pool.end();
    pool = new Pool({ ...connection, user: 'openpc_configuration_runtime', max: 2 });
    const restarted = new PostgresExplorerCustody(pool, scope);
    await assert.rejects(createPrivacyExplorerService(harness.port, restarted, redact).read(input));
    assert.equal(contacts, 1);
    const readback = await restarted.transaction(
      async (client) =>
        (
          await client.query(
            'select disposition,evidence_digest from control.privacy_explorer_execution where occurrence_id=$1',
            [context.occurrenceId],
          )
        ).rows[0],
    );
    assert.equal(readback.disposition, 'RELEASE_AUTHORIZED');
    assert.match(readback.evidence_digest, /^sha256:/);
    const foreign = new PostgresExplorerCustody(pool, { ...scope, privacyDomainId: uuidv7() });
    assert.equal(
      await foreign.transaction(
        async (client) =>
          (
            await client.query(
              'select occurrence_id from control.privacy_explorer_execution where occurrence_id=$1',
              [context.occurrenceId],
            )
          ).rowCount,
      ),
      0,
    );
    process.stdout.write(
      'OPENPC_EXPLORER_CUSTODY|PASS|cas|single-claim|opaque-cursor|restart-no-replay|tenant-isolation|durable-audit|generation-fence\n',
    );
  } finally {
    key.fill(0);
    await pool.end();
  }
}
