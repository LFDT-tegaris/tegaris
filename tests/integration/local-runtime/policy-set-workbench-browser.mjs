import {
  openPolicySimulation,
  policyAuthorHeading,
  selectPolicyVersion,
  importPolicyDocument,
} from './evaluation-ui-browser.mjs';
import assert from 'node:assert/strict';
import { publicReadResponse } from './authenticated-http.mjs';
import { execFile } from 'node:child_process';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';
import { expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { Pool } from 'pg';

const endpoint = '/api/v1/ui/policy-sets';
const load = async (path) => JSON.parse(await readFile(path, 'utf8'));
const save = async (path, value) => writeFile(path, JSON.stringify(value), { mode: 0o600 });

async function openPolicySetCreation(page) {
  const creation = page.getByRole('dialog', { name: 'Create a policy set', exact: true });
  if (!(await creation.isVisible()))
    await page.getByRole('button', { name: 'Create a policy set', exact: true }).click();
  await expect(creation).toBeVisible();
}

// The intercepted response is produced by the real owner before transport loss.
// Persist its exact request so a diagnostic continuation never invents new intent.
export async function createPolicySetDraft(page, name, checkpoint) {
  let committed = await load(checkpoint).catch((error) => {
    if (error.code !== 'ENOENT') throw error;
    return undefined;
  });
  if (!committed) {
    await openPolicySetCreation(page);
    await page.getByLabel('New policy set name', { exact: true }).fill(name);
    await page
      .getByRole('textbox', { name: 'Reason for creating this policy set', exact: true })
      .fill('Create an isolated draft for real policy authoring; no runtime activation.');
    let interceptionError;
    await page.route(`**${endpoint}`, async (route) => {
      if (route.request().method() !== 'POST') return route.continue();
      try {
        const request = route.request().postDataJSON();
        const response = await route.fetch();
        assert.equal(
          response.status(),
          201,
          'Real policy-set owner must commit before response loss',
        );
        committed = { request, result: await response.json() };
        await save(checkpoint, committed);
      } catch (error) {
        interceptionError = error;
      }
      await route.abort('failed');
    });
    await page.getByRole('button', { name: 'Create policy set draft', exact: true }).click();
    await expect(
      page.getByText(/The result could not be confirmed\. Retry the unchanged draft/u),
    ).toBeVisible();
    await page.unroute(`**${endpoint}`);
    if (interceptionError) throw interceptionError;
    assert.ok(committed);
    await page.reload();
    await openPolicySetCreation(page);
    await expect(page.getByLabel('New policy set name', { exact: true })).toHaveValue(name);
    const replayResponse = page.waitForResponse(
      (response) =>
        new URL(response.url()).pathname === endpoint && response.request().method() === 'POST',
    );
    await page.getByRole('button', { name: 'Create policy set draft', exact: true }).click();
    const replay = await replayResponse;
    assert.equal(replay.status(), 201);
    assert.deepEqual(replay.request().postDataJSON(), committed.request);
    assert.deepEqual(await replay.json(), committed.result);
    await expect(
      page.getByText('Draft created and read back. It grants no runtime authority.'),
    ).toBeVisible();
  } else {
    const replay = await page.evaluate(
      async ({ endpoint, request }) => {
        const response = await fetch(endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(request),
        });
        return { status: response.status, body: await response.json() };
      },
      { endpoint, request: committed.request },
    );
    assert.equal(replay.status, 201);
    assert.deepEqual(replay.body, committed.result);
    await page.reload();
  }
  const creation = page.getByRole('dialog', { name: 'Create a policy set', exact: true });
  if (await creation.isVisible()) {
    await page.getByRole('button', { name: 'Close Create a policy set', exact: true }).click();
    await expect(creation).not.toBeVisible();
  }
  const policySetId = `urn:openpc:policy-set:${committed.result.operation.resourceRef.slice(-36)}`;
  await page.getByLabel('Policy set for this version', { exact: true }).selectOption(policySetId);
  const resource = await page.evaluate(
    async ({ endpoint, policySetId }) => {
      const response = await fetch(`${endpoint}?policySetId=${encodeURIComponent(policySetId)}`);
      return { status: response.status, body: await response.json() };
    },
    { endpoint, policySetId },
  );
  assert.equal(resource.status, 200);
  assert.equal(resource.body.policySetId, policySetId);
  assert.equal(resource.body.state, 'DRAFT');
  assert.equal(resource.body.activeVersionDigest, null);
  assert.equal(resource.body.name, name);
  const denied = await page.evaluate(
    async ({ endpoint, request }) => {
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...request, activeVersionDigest: `sha256:${'ab'.repeat(32)}` }),
      });
      return response.status;
    },
    { endpoint, request: committed.request },
  );
  assert.equal(denied, 400, 'Workbench cannot fabricate activation');
  return { policySetId, operation: committed.result.operation };
}

async function main() {
  const { withTransactionBrowser } = await import('./transaction-workbench-browser.mjs');
  const { decodeBffSession } =
    await import('../../../apps/admin-web/app/api/v1/ui/local-runtime.ts');
  const [secretRoot, evidenceRoot, inputFile] = process.argv.slice(2);
  await promisify(execFile)(
    'bash',
    ['scripts/maintenance/run-bounded.sh', '--profile', 'runtime-target', '--reuse', '--', 'true'],
    { maxBuffer: 1024 * 1024 },
  );
  const input = await load(inputFile);
  const artifacts = join(
    evidenceRoot,
    'policy-set-browser',
    new Date().toISOString().replace(/[.:]/gu, '-'),
  );
  const pool = new Pool({
    host: '127.0.0.1',
    port: 55432,
    database: 'openpc_control',
    user: 'openpc_control',
    password: (await readFile(join(secretRoot, 'control_pg_password.txt'), 'utf8')).trim(),
    max: 1,
  });
  let poolClosed = false;
  try {
    await withTransactionBrowser(
      {
        secretRoot,
        evidenceRoot,
        artifacts,
        route: '/develop/modules',
        privacyDomainId: input.privacyDomainId,
        reuseSessions: true,
      },
      async ({ maker }) => {
        maker.setDefaultTimeout(20_000);
        await maker.goto('http://localhost:8080/configure/policies');
        await expect(
          maker.getByRole('heading', { name: policyAuthorHeading(), exact: true }),
        ).toBeVisible();
        await openPolicySetCreation(maker);
        await maker.getByLabel('New policy set name', { exact: true }).focus();
        await maker.keyboard.press('Tab');
        await expect(
          maker.getByRole('textbox', { name: 'Reason for creating this policy set', exact: true }),
        ).toBeFocused();
        const draft = await createPolicySetDraft(
          maker,
          input.name,
          join(evidenceRoot, 'policy-set-draft-operation.json'),
        );
        await maker.getByLabel('Semantic version', { exact: true }).fill(input.semanticVersion);
        await maker.getByLabel('Policy source', { exact: true }).selectOption('DOCUMENT');
        await importPolicyDocument(maker, input.semanticDocument);
        const existing = await pool.query(
          'select policy_version_id::text id from control.policy_version where participant_id=$1 and privacy_domain_id=$2 and policy_id=$3 and version=$4',
          [
            input.participantId,
            input.privacyDomainId,
            draft.policySetId.slice(-36),
            input.semanticVersion,
          ],
        );
        let versionId;
        if (existing.rowCount === 0) {
          assert.notEqual(
            process.env.OPENPC_POLICY_SET_RESUME_READBACK,
            '1',
            'Readback continuation requires the original committed version',
          );
          const responsePromise = maker.waitForResponse(
            (response) =>
              response.url().endsWith('/actions/create-version') &&
              response.request().method() === 'POST',
          );
          await maker
            .getByRole('button', { name: 'Create immutable version', exact: true })
            .click();
          const response = await responsePromise;
          assert.equal(
            response.status(),
            202,
            `Public version handoff returned ${response.status()}`,
          );
          const operation = await response.json();
          versionId = operation.resourceRef.slice(-36);
          await save(join(artifacts, 'version-operation.json'), operation);
        } else {
          assert.equal(existing.rowCount, 1);
          versionId = existing.rows[0].id;
          await openPolicySimulation(maker);
          await selectPolicyVersion(maker, versionId, draft.policySetId);
        }
        const rows = (
          await pool.query(
            `select p.policy_id::text,p.state::text,p.row_version::text,v.policy_version_id::text,v.semantic_digest,v.semantic_cbor,a.payload_digest
        from control.policy p join control.policy_version v using(participant_id,privacy_domain_id,policy_id)
        join control.policy_artifact a on a.policy_id=v.policy_id and a.participant_id=v.participant_id and a.privacy_domain_id=v.privacy_domain_id and a.semantic_digest=v.semantic_digest
        where p.participant_id=$1 and p.privacy_domain_id=$2 and p.policy_id=$3 and v.policy_version_id=$4`,
            [input.participantId, input.privacyDomainId, draft.policySetId.slice(-36), versionId],
          )
        ).rows;
        assert.equal(rows.length, 1);
        assert.equal(rows[0].state, 'EDITABLE_DRAFT');
        assert.equal(rows[0].row_version, '1');
        assert.equal(`sha256:${rows[0].semantic_digest.toString('hex')}`, input.semanticDigest);
        assert.ok(rows[0].semantic_cbor.length > 0 && rows[0].payload_digest.length === 32);
        assert.equal(
          (
            await pool.query(
              'select count(*)::int n from control.policy_generation where policy_version_id=$1',
              [versionId],
            )
          ).rows[0].n,
          0,
        );
        assert.equal(
          (
            await pool.query(
              'select count(*)::int n from control.policy where participant_id=$1 and privacy_domain_id=$2 and policy_name=$3',
              [input.participantId, input.privacyDomainId, input.name],
            )
          ).rows[0].n,
          1,
        );
        assert.equal(
          (
            await pool.query(
              'select count(*)::int n from control.mutation_evidence where operation_id=$1',
              [draft.operation.operationId],
            )
          ).rows[0].n,
          1,
        );
        assert.equal(
          (
            await pool.query(
              "select count(*)::int n from control.outbox_event where aggregate_id=$1 and event_type='policy-set.created.v1'",
              [draft.policySetId.slice(-36)],
            )
          ).rows[0].n,
          1,
        );
        const readVersion = async (recovering = false) => {
          const cookie = (await maker.context().cookies()).find(
            (item) => item.name === 'openpc_local_runtime_session',
          );
          const key = Buffer.from(
            (await readFile(join(secretRoot, 'bff_cookie_key.txt'), 'utf8')).trim(),
          );
          const session = decodeBffSession(cookie?.value, key);
          assert.ok(session?.sessionToken);
          for (let attempt = 0; attempt < (recovering ? 40 : 1); attempt++) {
            const response = await fetch(
              `http://127.0.0.1:8080/api/v1/policy-versions/urn:openpc:policy-version:${versionId}`,
              {
                headers: {
                  'Cookie': `__Host-openpc_session=${session.sessionToken}`,
                  'OpenPC-Participant-ID': `urn:openpc:participant:${input.participantId}`,
                  'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${input.privacyDomainId}`,
                  'OpenPC-API-Version': '1',
                  'X-Request-ID': draft.operation.operationId,
                },
              },
            );
            const version = await publicReadResponse(response, recovering);
            if (version === null) {
              await delay(250);
              continue;
            }
            assert.equal(version.policySetId, draft.policySetId);
            assert.equal(version.normalizedPolicyDigest, input.semanticDigest);
            return version;
          }
          throw new Error('Original policy version did not recover after owner restart');
        };
        // Policy versions and policy-set collections have different service
        // owners. Container health and version readback do not establish the
        // BFF collection path needed by the next browser reload after restart.
        const readPolicySet = async (recovering = false) => {
          for (let attempt = 0; attempt < (recovering ? 40 : 1); attempt++) {
            const response = await maker.request.get(`http://localhost:8080${endpoint}`);
            let collection;
            try {
              collection = await publicReadResponse(
                new Response(await response.body(), {
                  status: response.status(),
                  headers: response.headers(),
                }),
                recovering,
              );
            } finally {
              await response.dispose();
            }
            if (collection === null) {
              if (attempt === 0)
                process.stdout.write(
                  'OPENPC_POLICY_SET_BROWSER|waiting-original-collection-after-restart\n',
                );
              await delay(250);
              continue;
            }
            assert.ok(Array.isArray(collection.items));
            const matches = collection.items.filter(
              (item) => item.policySetId === draft.policySetId,
            );
            assert.equal(matches.length, 1);
            assert.equal(matches[0].participantId, `urn:openpc:participant:${input.participantId}`);
            assert.equal(matches[0].name, input.name);
            return matches[0];
          }
          throw new Error('Original policy-set collection did not recover after owner restart');
        };
        const versionBefore = await readVersion();
        const policySetBefore = await readPolicySet();
        await pool.end();
        poolClosed = true;
        if (
          process.env.OPENPC_POLICY_SET_COMPOSE_JSON &&
          process.env.OPENPC_POLICY_SET_RESUME_READBACK !== '1'
        ) {
          const compose = JSON.parse(process.env.OPENPC_POLICY_SET_COMPOSE_JSON);
          assert.ok(Array.isArray(compose) && compose[0] === 'docker' && compose[1] === 'compose');
          const { stdout } = await promisify(execFile)(
            compose[0],
            [...compose.slice(1), 'ps', '--services', '--status', 'running'],
            { timeout: 10_000 },
          );
          const running = new Set(stdout.trim().split('\n'));
          for (const owner of ['control-pg', 'identity-service', 'policy-service', 'control-api'])
            assert.ok(running.has(owner), `Policy restart owner unavailable: ${owner}`);
          const services = [
            'identity-service',
            'policy-service',
            'participant-service',
            'control-worker',
            'control-api',
          ].filter((service) => running.has(service));
          process.stdout.write('OPENPC_POLICY_SET_BROWSER|restart-owners\n');
          // Quiesce every live Control-store consumer before its database, then
          // restore only that admitted live set. Stopped services stay stopped.
          await promisify(execFile)(compose[0], [...compose.slice(1), 'stop', ...services], {
            timeout: 60_000,
          });
          await promisify(execFile)(compose[0], [...compose.slice(1), 'restart', 'control-pg'], {
            timeout: 60_000,
          });
          await promisify(execFile)(
            compose[0],
            [
              ...compose.slice(1),
              'up',
              '-d',
              '--wait',
              '--no-recreate',
              '--no-deps',
              '--no-build',
              '--pull',
              'never',
              'control-pg',
              ...services,
            ],
            { timeout: 60_000 },
          );
          assert.deepEqual(await readVersion(true), versionBefore);
          assert.deepEqual(await readPolicySet(true), policySetBefore);
        }
        await maker.reload();
        await expect(maker.getByLabel('Policy set for this version', { exact: true })).toHaveValue(
          draft.policySetId,
        );
        await openPolicySimulation(maker);
        await selectPolicyVersion(maker, versionId, draft.policySetId);
        for (const width of [1440, 360]) {
          await maker.setViewportSize({ width, height: 1000 });
          const axe = await new AxeBuilder({ page: maker })
            .withTags(['wcag2a', 'wcag2aa', 'wcag21aa'])
            .analyze();
          assert.deepEqual(
            axe.violations.map(({ id, impact }) => ({ id, impact })),
            [],
          );
          assert.equal(
            await maker.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
            true,
          );
          await maker.screenshot({
            path: join(artifacts, `policy-set-${width}.png`),
            fullPage: true,
          });
        }
        await save(join(evidenceRoot, 'policy-set-result.json'), {
          ...draft,
          versionId,
          semanticVersion: input.semanticVersion,
          artifacts,
        });
        process.stdout.write(
          'OPENPC_POLICY_SET_BROWSER|PASS|public-draft|lost-response|same-key-replay|one-effect|real-version-parent|no-activation|reload|keyboard|axe|360px\n',
        );
      },
    );
  } finally {
    if (!poolClosed) await pool.end();
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
