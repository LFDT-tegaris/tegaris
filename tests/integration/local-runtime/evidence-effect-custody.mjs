import {
  verifyDeploymentProvenanceSources,
  verifyDeploymentHoldSources,
  verifyReceiptProvenanceSources,
  verifyPublicProvenance,
} from './evidence-provenance-checks.mjs';
import { inspectProvenanceWorkbench } from './evidence-provenance-browser.mjs';
import { verifyDeploymentRetirementSource } from './evidence-deployment-retirement-checks.mjs';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createECDH, randomBytes } from 'node:crypto';
import { chmod, mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { Pool } from 'pg';
import { expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import {
  governThroughWorkbench,
  withTransactionBrowser,
} from './transaction-workbench-browser.mjs';
import { readEffectEvidenceSources } from '../../../services/control-api/src/evidence/effect-source.ts';
import { selectDeploymentResultSource } from '../../../services/control-api/src/configuration/deployment/result-source.ts';
import { verifyDeploymentResult } from '../../../services/control-api/src/configuration/deployment/result-verification.ts';
import { readDeploymentResult } from '../../../services/control-api/src/configuration/deployment/result-readback.ts';
import { LocalEvidenceVault } from '../../../services/control-api/src/evidence/local-vault.ts';
import { inspectSegment, openSegment } from '../../../services/control-api/src/evidence/segment.ts';
import { sha256 } from '../../../services/control-api/src/configuration/digest.ts';
import { uuidv7 } from '../../../services/control-api/src/configuration/governed-mutation-http.ts';

// SEM-053/054/055/058/061: run after real governed deployment transitions.
// No command, reservation, execution, projection or approval is seeded here.
const exec = promisify(execFile);
await exec('bash', [
  'scripts/maintenance/run-bounded.sh',
  '--profile',
  'runtime-target',
  '--reuse',
  '--',
  'true',
]);
const [secretRoot, participantId, privacyDomainId, session, composeJson] = process.argv.slice(2);
const compose = JSON.parse(composeJson);
assert.equal(compose[0], 'docker');
assert.equal(compose[1], 'compose');
const root = await mkdtemp(join(secretRoot, '..', 'data', 'evidence-effect-'));
const scope = { participantId, privacyDomainId, streamId: `deployment-effects-${uuidv7()}` };
const config = { host: '127.0.0.1', port: 55432, database: 'openpc_control', max: 1 };
const admin = new Pool({
  ...config,
  user: 'openpc_control',
  password: (await readFile(join(secretRoot, 'control_pg_password.txt'), 'utf8')).trim(),
});
const worker = new Pool({
  ...config,
  user: 'openpc_local_control_worker',
  password: (
    await readFile(join(secretRoot, 'control_worker_runtime_db_password.txt'), 'utf8')
  ).trim(),
});
const runtime = new Pool({
  ...config,
  user: 'openpc_configuration_runtime',
  password: (
    await readFile(join(secretRoot, 'control_api_runtime_db_password.txt'), 'utf8')
  ).trim(),
});
const encryption = randomBytes(32);
const keyId = 'deployment-effects-key';
const fields = [participantId, privacyDomainId, scope.streamId];
const count = async (table) =>
  (
    await admin.query(
      `select count(*)::int count from control.${table} where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3`,
      fields,
    )
  ).rows[0].count;
try {
  const sources = (
    await admin.query(
      `select command_id::text,sequence::text,signed_bytes,result_digest from control.deployment_result
     where participant_id=$1 and privacy_domain_id=$2 order by created_at,command_id,sequence`,
      fields.slice(0, 2),
    )
  ).rows;
  assert.ok(sources.length > 0 && sources.length <= 512, 'real deployment observations required');
  assert.ok(
    (
      await admin.query(
        'select 1 from control.authentication_occurrence where participant_id=$1 and privacy_domain_id=$2 limit 1',
        fields.slice(0, 2),
      )
    ).rowCount === 1,
    'real scoped authentication source prerequisite',
  );
  const requireInvalidation =
    process.env.OPENPC_LOCAL_RUNTIME_TRANSACTION_BROWSER !== '1' &&
    (process.env.OPENPC_LOCAL_RUNTIME_DEPLOYMENT_CASES ?? 'direct')
      .split(/\s+/u)
      .includes('direct');
  const requireRejection =
    process.env.OPENPC_LOCAL_RUNTIME_TRANSACTION_BROWSER !== '1' &&
    (process.env.OPENPC_LOCAL_RUNTIME_DEPLOYMENT_CASES ?? 'direct native')
      .split(/\s+/u)
      .includes('native');
  if (requireRejection)
    assert.ok(
      sources.some(
        (row) =>
          JSON.parse(row.signed_bytes.toString('utf8')).claims.schema ===
          'PC-DEPLOYMENT-RESERVATION-REJECTION-1',
      ),
      'the competing Native Value command has its own signed pre-handoff rejection',
    );
  const states = new Set(
    sources.map((row) => JSON.parse(row.signed_bytes.toString('utf8')).claims.status?.state),
  );
  if (requireInvalidation) {
    assert.ok(states.has('CONFIRMED'), 'a real confirmed effect must have occurred');
    assert.ok(
      states.has('REORG') || states.has('FAILED'),
      'later invalidation must remain distinct',
    );
  }
  const container = (
    await exec(compose[0], [...compose.slice(1), 'ps', '-q', 'control-api'])
  ).stdout.trim();
  const running = JSON.parse((await exec('docker', ['inspect', container])).stdout)[0];
  const built = JSON.parse(
    (await exec('docker', ['image', 'inspect', 'openpc-r1-dev/control-api:local'])).stdout,
  )[0];
  assert.equal(running.Image, built.Id);
  assert.equal(built.Config.Labels['io.openpc.image.service'], 'control-api');
  for (const [from, to] of [
    ['/app/evidence-worker.mjs', 'evidence-worker.mjs'],
    ['/app/result-source.sql', 'result-source.sql'],
    ['/usr/local/bin/openpc-policy-evaluator', 'openpc-policy-evaluator'],
  ])
    await exec('docker', ['cp', `${container}:${from}`, join(root, to)]);
  await chmod(join(root, 'openpc-policy-evaluator'), 0o700);
  await writeFile(join(root, 'encryption.key'), encryption, { mode: 0o600, flag: 'wx' });
  const configuration = join(root, 'worker.json');
  await writeFile(
    configuration,
    JSON.stringify({
      database: {
        ...config,
        max: undefined,
        user: 'openpc_local_control_worker',
        passwordFile: join(secretRoot, 'control_worker_runtime_db_password.txt'),
      },
      vaultDirectory: join(root, 'vault'),
      sinkId: 'deployment-effects-local-sink',
      scopes: [
        {
          ...scope,
          source: 'EFFECT',
          activeKeyId: keyId,
          keys: [{ keyId, keyFile: join(root, 'encryption.key') }],
          retentionSeconds: 86400,
          capacityBytes: 16 * 1024 * 1024,
        },
        // Deployment-only runs do not execute the separate authentication
        // browser. Catalogue its actual Identity receipts through the packaged
        // custody owner before the cross-family provenance assertions below.
        {
          ...scope,
          streamId: `${scope.streamId}-authentication`,
          source: 'AUTHENTICATION',
          activeKeyId: keyId,
          keys: [{ keyId, keyFile: join(root, 'encryption.key') }],
          retentionSeconds: 86400,
          capacityBytes: 16 * 1024 * 1024,
        },
      ],
    }),
    { mode: 0o600 },
  );
  const environment = {
    ...process.env,
    OPENPC_EVIDENCE_WORKER_CONFIG_FILE: configuration,
    OPENPC_POLICY_CORE_BIN: join(root, 'openpc-policy-evaluator'),
    OPENPC_DEPLOYMENT_PROJECTION_PUBLIC_KEY_FILE: join(
      secretRoot,
      'runtime_agent_projection_public_key.txt',
    ),
    OPENPC_DEPLOYMENT_REJECTION_PUBLIC_KEY_FILE: join(
      secretRoot,
      'fleet_deployment_rejection_public_key.txt',
    ),
  };
  const run = (env = environment) =>
    exec(process.execPath, [join(root, 'evidence-worker.mjs'), '--once'], {
      env,
      timeout: 30000,
      maxBuffer: 65536,
    });
  const wrong = createECDH('secp256k1');
  wrong.generateKeys();
  await writeFile(join(root, 'wrong-public-key'), wrong.getPublicKey('hex', 'compressed'));
  await assert.rejects(
    run({
      ...environment,
      OPENPC_DEPLOYMENT_PROJECTION_PUBLIC_KEY_FILE: join(root, 'wrong-public-key'),
      OPENPC_DEPLOYMENT_REJECTION_PUBLIC_KEY_FILE: join(root, 'wrong-public-key'),
    }),
    (error) => {
      assert.equal(error.code, 1);
      assert.match(error.stderr, /"phase":"ingest","code":"INTEGRITY"/u);
      assert.equal(error.stderr.includes(participantId), false);
      return true;
    },
  );
  assert.equal(await count('evidence_catalogue'), 0);
  assert.equal(await count('evidence_checkpoint'), 0);

  Object.assign(process.env, environment);
  const client = await worker.connect();
  try {
    await client.query('begin');
    await client.query(
      `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_EXPORT_RECORDS-V1',true)`,
      [participantId, privacyDomainId, uuidv7()],
    );
    const projection = sources.find(
      (row) =>
        JSON.parse(row.signed_bytes.toString('utf8')).claims.schema ===
        'PC-DEPLOYMENT-JOURNAL-PROJECTION-1',
    );
    const command = (projection ?? sources[0]).command_id;
    const binding = (
      await selectDeploymentResultSource(client, command, participantId, privacyDomainId)
    ).rows[0];
    if (projection) assert.ok(binding, 'original handoff and approved intent remain authoritative');
    const latest = await readDeploymentResult(client, command, participantId, privacyDomainId);
    assert.ok(latest, 'current public readback verifies the shared source');
    if (requireInvalidation)
      assert.ok(
        ['REORG', 'FAILED', 'REJECTED'].includes(latest.status.state),
        'current public readback retains invalidation',
      );
    if (binding) {
      const prior = sources.find(
        (row) => row.command_id === command && row.sequence !== binding.sequence,
      );
      if (requireInvalidation) assert.ok(prior, 'historical sequence must precede latest');
      const historical = prior ?? sources.find((row) => row.command_id === command);
      const original = verifyDeploymentResult(
        { ...binding, ...historical },
        command,
        participantId,
        privacyDomainId,
        false,
      );
      assert.equal(`sha256:${original.resultDigest}`, historical.result_digest);
      for (const altered of [
        { ...historical, signed_bytes: Buffer.concat([historical.signed_bytes, Buffer.from(' ')]) },
        { ...historical, sequence: '18446744073709551615' },
        { ...historical, result_digest: `sha256:${'00'.repeat(32)}` },
      ])
        assert.throws(() =>
          verifyDeploymentResult(
            { ...binding, ...altered },
            command,
            participantId,
            privacyDomainId,
            false,
          ),
        );
      for (const [operation, participant, privacy] of [
        [uuidv7(), participantId, privacyDomainId],
        [command, uuidv7(), privacyDomainId],
        [command, participantId, uuidv7()],
      ])
        assert.throws(() =>
          verifyDeploymentResult(
            { ...binding, ...historical },
            operation,
            participant,
            privacy,
            false,
          ),
        );
    } else {
      assert.equal(latest.identity, 'PC-DEPLOYMENT-RESERVATION-REJECTION-1');
      assert.equal(requireInvalidation, false);
    }
    await client.query('rollback');
    for (const [participant, privacy] of [
      [participantId, uuidv7()],
      [uuidv7(), privacyDomainId],
    ]) {
      await client.query('begin');
      await client.query(
        `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_EXPORT_RECORDS-V1',true)`,
        [participant, privacy, uuidv7()],
      );
      assert.deepEqual(
        await readEffectEvidenceSources(client, scope),
        [],
        'RLS forbids cross-context source reads',
      );
      await client.query('rollback');
    }
  } finally {
    await client.query('rollback');
    client.release();
  }
  // Each process starts independently; stream locking and durable source IDs
  // preserve admission once across concurrent selection and process restarts.
  await Promise.all([run(), run()]);
  // A format boundary can end an object before the eight-record limit. Drain
  // by authoritative admission progress, preserving every original in order.
  for (
    let batch = 0;
    batch < sources.length && (await count('evidence_catalogue')) < sources.length;
    batch++
  )
    await run();
  assert.equal(await count('evidence_catalogue'), sources.length);
  const before = await count('evidence_checkpoint');
  await run();
  assert.equal(await count('evidence_catalogue'), sources.length);
  assert.equal(await count('evidence_checkpoint'), before);
  const vault = await LocalEvidenceVault.open(join(root, 'vault'), 'deployment-effects-local-sink');
  const checkpoints = (
    await admin.query(
      `select receipt from control.evidence_checkpoint where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 order by through_sequence`,
      fields,
    )
  ).rows;
  const records = [];
  for (const checkpoint of checkpoints) {
    const bytes = await vault.read(checkpoint.receipt.object);
    const segment = inspectSegment(bytes);
    records.push(...openSegment(bytes, segment.objectDigest, segment.header, encryption).records);
  }
  assert.equal(records.length, sources.length);
  for (const [index, record] of records.entries()) {
    const source = sources[index];
    assert.equal(record.recordId, `deployment:${source.command_id}:${source.sequence}`);
    assert.equal(record.evidenceClass, 'EFFECT');
    assert.equal(record.receiptDigest, sha256(source.signed_bytes));
    assert.deepEqual(Buffer.from(record.receiptBase64, 'base64'), source.signed_bytes);
    const claims = JSON.parse(source.signed_bytes.toString('utf8')).claims;
    assert.equal(record.sourceFormat, claims.schema);
    assert.equal(Date.parse(record.occurredAt), Date.parse(claims.observedAt));
  }
  const catalogue = await admin.query(
    `select evidence_id::text id,receipt_digest from control.evidence_catalogue where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3`,
    fields,
  );
  const publicHeaders = {
    'Cookie': `__Host-openpc_session=${session}`,
    'OpenPC-API-Version': '1',
    'OpenPC-Participant-ID': `urn:openpc:participant:${participantId}`,
    'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacyDomainId}`,
    'X-Request-ID': uuidv7(),
    'X-Correlation-ID': uuidv7(),
  };
  const firstCatalogue = catalogue.rows[0];
  const rangeUrl = `http://127.0.0.1:8080/api/v1/evidence-records/urn:openpc:resource:${firstCatalogue.id}/export-range`;
  const rangeResponse = await fetch(rangeUrl, { headers: publicHeaders });
  assert.equal(rangeResponse.status, 200);
  const rangeView = await rangeResponse.json();
  assert.equal(rangeView.range.streamId, scope.streamId);
  assert.equal(rangeView.recordDigest, firstCatalogue.receipt_digest);
  const foreignRange = await fetch(rangeUrl, {
    headers: {
      ...publicHeaders,
      'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${uuidv7()}`,
    },
  });
  assert.equal(foreignRange.status, 403);
  assert.equal((await foreignRange.json()).code, 'PC-AUTH-0005');
  assert.equal((await fetch(rangeUrl, { headers: { ...publicHeaders, Cookie: '' } })).status, 401);
  for (const row of catalogue.rows) {
    const response = await fetch(
      `http://127.0.0.1:8080/api/v1/evidence-records/urn:openpc:resource:${row.id}`,
      {
        headers: {
          'Cookie': `__Host-openpc_session=${session}`,
          'OpenPC-API-Version': '1',
          'OpenPC-Participant-ID': `urn:openpc:participant:${participantId}`,
          'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacyDomainId}`,
          'X-Request-ID': uuidv7(),
          'X-Correlation-ID': uuidv7(),
        },
      },
    );
    assert.equal(response.status, 200, 'authorized public effect catalogue read');
    assert.equal(response.headers.get('cache-control'), 'no-store');
    const view = await response.json();
    assert.equal(view.evidenceClass, 'EFFECT');
    assert.equal(view.recordDigest, row.receipt_digest);
    assert.deepEqual(
      Object.keys(view).sort(),
      [
        'evidenceId',
        'participantId',
        'evidenceClass',
        'recordDigest',
        'sequence',
        'state',
        'occurredAt',
        'revision',
        'createdAt',
        'updatedAt',
      ].sort(),
    );
  }
  const provenanceClient = await worker.connect();
  let provenanceViews;
  try {
    await provenanceClient.query('begin isolation level repeatable read read only');
    await provenanceClient.query(
      `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_RECORDS_READ_RESOURCE-V1',true)`,
      [participantId, privacyDomainId, uuidv7()],
    );
    provenanceViews = await verifyDeploymentProvenanceSources(
      provenanceClient,
      participantId,
      privacyDomainId,
    );
    const sourceHolds = await verifyDeploymentHoldSources(
      provenanceClient,
      participantId,
      privacyDomainId,
      provenanceViews,
    );
    if (requireInvalidation) assert.ok(sourceHolds.anchored > 0);
    if (states.has('REORG')) assert.ok(sourceHolds.reorg > 0);
    provenanceViews.push(
      ...(await verifyReceiptProvenanceSources(provenanceClient, participantId, privacyDomainId, [
        'OPENPC_AUTHENTICATION_OCCURRENCE_V1',
        'COSE_SIGN1_24001_1_338',
        ...(requireRejection ? ['PC-DEPLOYMENT-RESERVATION-REJECTION-1'] : []),
      ])),
    );
  } finally {
    await provenanceClient.query('rollback');
    provenanceClient.release();
  }
  await verifyDeploymentRetirementSource({
    admin,
    runtime,
    worker,
    scope,
    requireClosed: false,
    requireReorg: states.has('REORG'),
  });
  await verifyPublicProvenance(
    async (path, context = {}) => {
      const response = await fetch(`http://127.0.0.1:8080/api/v1/${path}`, {
        headers: {
          ...publicHeaders,
          'OpenPC-Participant-ID': `urn:openpc:participant:${context.participantId ?? participantId}`,
          'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${context.privacyDomainId ?? privacyDomainId}`,
        },
      });
      assert.equal(response.headers.get('cache-control'), 'no-store');
      return { status: response.status, body: await response.json() };
    },
    provenanceViews,
    secretRoot,
  );
  const artifacts = join(secretRoot, '..', 'evidence', 'effect-custody-browser');
  await mkdir(artifacts, { recursive: true, mode: 0o700 });
  const retainedActors = await readFile(join(artifacts, 'deployment-intent-actors.json')).catch(
    (error) => {
      if (error.code !== 'ENOENT') throw error;
      return null;
    },
  );
  if (retainedActors === null)
    await exec(
      process.execPath,
      [
        '--import',
        'tsx',
        'tests/integration/local-runtime/deployment-intent-actors.mjs',
        secretRoot,
        artifacts,
        participantId,
        'bootstrap-evidence',
      ],
      { timeout: 30000, maxBuffer: 65536 },
    );
  await withTransactionBrowser(
    { secretRoot, evidenceRoot: artifacts, artifacts, route: '/operate/evidence' },
    async ({ maker, checker, actors }) => {
      await expect(maker.getByText('Scoped evidence loaded.', { exact: true })).toBeVisible();
      await inspectProvenanceWorkbench(
        maker,
        provenanceViews.find((view) => view.deployment?.historical.finality === 'FINALIZED') ??
          provenanceViews[0],
        artifacts,
      );
      for (const family of ['authentication', 'business', 'rejection']) {
        const example = provenanceViews.find((view) => view[family]);
        if (example) await inspectProvenanceWorkbench(maker, example, artifacts);
      }
      await maker.getByRole('button', { name: 'Refresh evidence', exact: true }).click();
      await expect(maker.getByText('Scoped evidence loaded.', { exact: true })).toBeVisible();
      const region = maker.getByRole('region', { name: 'Evidence catalogue' });
      await expect(region).toContainText('EFFECT');
      const displayed = await region.innerText();
      const visibleSource = records.find((record) => displayed.includes(record.receiptDigest));
      assert.ok(visibleSource, 'the first catalogue page displays an exact archived effect');
      const refreshed = maker.waitForResponse(
        (response) => new URL(response.url()).pathname === '/api/v1/ui/evidence-workbench',
      );
      await maker.getByRole('button', { name: 'Refresh evidence', exact: true }).focus();
      await maker.keyboard.press('Enter');
      assert.equal((await refreshed).status(), 200);
      await expect(region).toContainText(visibleSource.receiptDigest);
      const selectedRecord = catalogue.rows.find(
        (row) => row.receipt_digest === visibleSource.receiptDigest,
      );
      assert.ok(selectedRecord);
      const chosen = region.getByRole('listitem').filter({ hasText: selectedRecord.id });
      const discovered = maker.waitForResponse(
        (response) => new URL(response.url()).searchParams.get('recordId') === selectedRecord.id,
      );
      await chosen.getByRole('button', { name: /Select sequence/u }).click();
      const discoveryResponse = await discovered;
      assert.equal(discoveryResponse.status(), 200);
      const discovery = (await discoveryResponse.json()).record;
      assert.equal(discovery.recordDigest, visibleSource.receiptDigest);
      assert.equal(discovery.range.streamId, scope.streamId);
      await expect(maker.getByLabel('Evidence stream', { exact: true })).toHaveValue(
        scope.streamId,
      );
      await maker
        .getByLabel('Purpose', { exact: true })
        .fill('Export the selected verified effect observation.');
      const creating = maker.waitForResponse(
        (response) =>
          new URL(response.url()).pathname === '/api/v1/ui/evidence-workbench' &&
          response.request().method() === 'POST',
      );
      await maker.getByRole('button', { name: 'Create export request', exact: true }).click();
      const created = await creating;
      assert.equal(created.status(), 202);
      const resourceRef = (await created.json()).operation.resourceRef;
      const selectedRegion = maker.getByRole('region', { name: 'Selected export', exact: true });
      await expect(selectedRegion).toContainText('REQUESTED');
      const readStatus = async () => {
        const response = maker.waitForResponse(
          (value) => new URL(value.url()).searchParams.get('exportId') === resourceRef.slice(-36),
        );
        await maker
          .getByRole('button', { name: 'Read current export status', exact: true })
          .click();
        const actual = await response;
        assert.equal(actual.status(), 200);
        return actual.json();
      };
      const requested = await readStatus();
      assert.deepEqual(requested.selection.range, discovery.range);
      assert.equal(requested.selection.records.length, 1);
      const approved = await governThroughWorkbench({
        maker,
        checker,
        checkerId: actors.checker.principalId,
        label: 'Export selected evidence',
        fields: {
          'Resource reference': resourceRef,
          'Expected revision': requested.selected.revision,
          'Selected request digest': requested.selected.requestDigest,
        },
        reason: 'Release one minimized effect record under independent approval.',
      });
      assert.equal(approved.completed.operation.state, 'ACCEPTED');
      assert.equal((await readStatus()).selected.state, 'RUNNING');
      await run();
      assert.equal((await readStatus()).selected.state, 'SUCCEEDED');
      const retrieving = maker.waitForResponse(
        (response) => new URL(response.url()).searchParams.get('artifact') === '1',
      );
      await maker.getByRole('button', { name: 'Retrieve verified export', exact: true }).click();
      const retrieved = await retrieving;
      assert.equal(retrieved.status(), 200);
      const downloaded = (await retrieved.json()).download;
      assert.equal(downloaded.outputDigest, sha256(downloaded.artifact));
      assert.equal(downloaded.artifact.records.length, 1);
      assert.equal(downloaded.artifact.records[0].recordDigest, visibleSource.receiptDigest);
      await expect(
        maker.getByRole('button', { name: 'Download export JSON', exact: true }),
      ).toBeVisible();
      const accessibility = await new AxeBuilder({ page: maker })
        .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'])
        .analyze();
      assert.deepEqual(
        accessibility.violations.map((value) => value.id),
        [],
      );
      await maker.screenshot({ path: join(artifacts, 'effects-desktop.png'), fullPage: true });
      await maker.setViewportSize({ width: 360, height: 900 });
      assert.equal(
        await maker.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
        true,
      );
      await maker.screenshot({ path: join(artifacts, 'effects-reflow.png'), fullPage: true });
    },
  );
  process.stdout.write(
    `OPENPC_EFFECT_EVIDENCE_CUSTODY|PASS|real-command-effects|historical-signatures|invalidation=${requireInvalidation ? 'passed' : 'outside-slice'}|pre-handoff-rejection=${requireRejection ? 'passed' : 'outside-slice'}|wrong-key-denied|scope-isolation|concurrent-once|packaged-worker-restart|encrypted-originals|safe-public-readback|browser-catalogue|discovered-range|governed-export|keyboard|axe|reflow\n`,
  );
} finally {
  encryption.fill(0);
  await worker.end();
  await runtime.end();
  await admin.end();
}
