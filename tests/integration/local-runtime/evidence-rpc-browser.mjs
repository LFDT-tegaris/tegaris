import assert from 'node:assert/strict';
import { verifyPublicProvenance } from './evidence-provenance-checks.mjs';
import { inspectProvenanceWorkbench } from './evidence-provenance-browser.mjs';
import { execFile } from 'node:child_process';
import { access, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import {
  governThroughWorkbench,
  withTransactionBrowser,
} from './transaction-workbench-browser.mjs';
import { publicEvidenceReader } from './evidence-rejection-deletion-checks.mjs';
import { evidenceExportDownload } from '../../../services/control-api/src/evidence/export-artifact.ts';
import { sha256 } from '../../../services/control-api/src/configuration/digest.ts';
import { uuidv7 } from '../../../services/control-api/src/configuration/governed-mutation-http.ts';
const exec = promisify(execFile);

export function rpcEvidenceForeignPrivacy(privacyDomainId) {
  // The isolated first-policy context already has the original bootstrap
  // context available. It must not depend on another journey creating 6201.
  const bootstrap = '018f0000-0000-7000-8000-000000000201';
  return privacyDomainId === bootstrap ? '018f0000-0000-7000-8000-000000006201' : bootstrap;
}

export async function rpcEvidenceBrowser({
  provenance,
  factProvenance = [],
  secretRoot,
  participantId,
  privacyDomainId,
  scope,
  root,
  catalogue,
  records,
  run,
  compose,
  retainedExportRef,
}) {
  const foreignPrivacy = rpcEvidenceForeignPrivacy(privacyDomainId);
  const actorRoot = join(root, 'browser');
  const artifacts = join(actorRoot, new Date().toISOString().replaceAll(':', '-'));
  await mkdir(artifacts, { recursive: true, mode: 0o700 });
  const existingActors = await access(join(actorRoot, 'deployment-intent-actors.json')).then(
    () => true,
    (error) => {
      if (error.code !== 'ENOENT') throw error;
      return false;
    },
  );
  if (!existingActors)
    await exec(
      process.execPath,
      [
        '--import',
        'tsx',
        'tests/integration/local-runtime/deployment-intent-actors.mjs',
        secretRoot,
        actorRoot,
        participantId,
        'bootstrap-evidence-rpc',
        privacyDomainId,
        foreignPrivacy,
      ],
      { timeout: 30000, maxBuffer: 65536 },
    );
  let selectedId, exportRef;
  await withTransactionBrowser(
    {
      secretRoot,
      evidenceRoot: actorRoot,
      artifacts,
      route: '/operate/evidence',
      privacyDomainId,
      reuseSessions: true,
    },
    async ({ maker, checker, actors }) => {
      await expect(maker.getByText('Scoped evidence loaded.', { exact: true })).toBeVisible();
      const api = await publicEvidenceReader(maker, secretRoot, participantId, privacyDomainId);
      for (const row of catalogue) {
        const view = await api(`evidence-records/urn:openpc:resource:${row.id}`);
        assert.equal(view.status, 200);
        assert.equal(view.body.recordDigest, row.receipt_digest);
        assert.deepEqual(
          Object.keys(view.body).sort(),
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
      await verifyPublicProvenance(api, provenance, secretRoot);
      const phaseExamples = [
        ...new Map(provenance.map((view) => [view.rpc.transition.phase, view])).values(),
      ];
      for (const view of phaseExamples) await inspectProvenanceWorkbench(maker, view, artifacts);
      await verifyPublicProvenance(api, factProvenance, secretRoot);
      for (const view of factProvenance) await inspectProvenanceWorkbench(maker, view, artifacts);
      await maker.reload();
      await expect(maker.getByText('Scoped evidence loaded.', { exact: true })).toBeVisible();
      const region = maker.getByRole('region', { name: 'Evidence catalogue' });
      await expect(region).toContainText('EFFECT');
      const displayed = await region.innerText();
      const visibleSource = records.find((record) => displayed.includes(record.receiptDigest));
      assert.ok(
        visibleSource,
        'the first catalogue page displays an exact archived RPC transition',
      );
      const refreshed = maker.waitForResponse(
        (response) => new URL(response.url()).pathname === '/api/v1/ui/evidence-workbench',
      );
      await maker.getByRole('button', { name: 'Refresh evidence', exact: true }).focus();
      await maker.keyboard.press('Enter');
      assert.equal((await refreshed).status(), 200);
      await expect(region).toContainText(visibleSource.receiptDigest);
      const selectedRecord = catalogue.find(
        (row) => row.receipt_digest === visibleSource.receiptDigest,
      );
      assert.ok(selectedRecord);
      selectedId = selectedRecord.id;
      const recordPath = `evidence-records/urn:openpc:resource:${selectedId}`;
      const denied = await api(recordPath, { participantId: uuidv7() });
      assert.equal(denied.status, 403);
      assert.equal(JSON.stringify(denied.body).includes(visibleSource.receiptDigest), false);
      const deletion = await api(`${recordPath}/deletion-plan`);
      assert.equal(deletion.status, 200);
      assert.equal(deletion.body.eligible, false);
      assert.ok(deletion.body.blockers.includes('UNSUPPORTED_SOURCE'));
      const chosen = region
        .getByRole('listitem')
        .filter({ hasText: visibleSource.receiptDigest })
        .first();
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
      let resourceRef = retainedExportRef;
      if (resourceRef) {
        assert.match(resourceRef, /^urn:openpc:resource:[0-9a-f-]{36}$/u);
        const existing = await api(`evidence-exports/${resourceRef}`);
        assert.equal(existing.status, 200);
        assert.equal(existing.body.state, 'SUCCEEDED');
      } else {
        await maker
          .getByLabel('Purpose', { exact: true })
          .fill('Export the selected verified RPC decision admission.');
        const creating = maker.waitForResponse(
          (response) =>
            new URL(response.url()).pathname === '/api/v1/ui/evidence-workbench' &&
            response.request().method() === 'POST',
        );
        await maker.getByRole('button', { name: 'Create export request', exact: true }).click();
        const created = await creating;
        assert.equal(created.status(), 202);
        resourceRef = (await created.json()).operation.resourceRef;
        await expect(
          maker.getByRole('region', { name: 'Selected export', exact: true }),
        ).toContainText('REQUESTED');
      }
      exportRef = resourceRef;
      const readStatus = async (review = false, allowUnavailable = false) => {
        const response = maker.waitForResponse(
          (value) => new URL(value.url()).searchParams.get('exportId') === resourceRef.slice(-36),
        );
        await maker
          .getByRole('button', {
            name: review ? `Review export ${resourceRef.slice(-36)}` : 'Read current export status',
            exact: true,
          })
          .click();
        const actual = await response;
        const body = await actual.json();
        if (allowUnavailable && actual.status() === 503) {
          assert.equal(body.code, 'PC-INTEGRATION-5001');
          assert.equal(body.retryable, true);
          await expect(
            maker.getByRole('status').filter({ hasText: 'The requested process is unavailable.' }),
          ).toBeVisible();
          process.stdout.write(
            'OPENPC_RPC_EXPORT_RECOVERY|transient-unavailable|same-request|safe-browser-retry\n',
          );
          return null;
        }
        assert.equal(actual.status(), 200, JSON.stringify(body));
        return body;
      };
      const requested = await readStatus(!!retainedExportRef);
      assert.deepEqual(requested.selection.range, discovery.range);
      assert.equal(requested.selection.records.length, 1);
      if (!retainedExportRef) {
        const approved = await governThroughWorkbench({
          maker,
          checker,
          checkerId: actors.checker.principalId,
          label: 'Export selected evidence',
          loseExecutionResponse: true,
          fields: {
            'Resource reference': resourceRef,
            'Expected revision': requested.selected.revision,
            'Selected request digest': requested.selected.requestDigest,
          },
          reason: 'Release one minimized RPC evidence record under independent approval.',
        });
        assert.equal(approved.completed.operation.state, 'ACCEPTED');
        assert.equal((await readStatus()).selected.state, 'RUNNING');
        await run();
        assert.equal((await readStatus()).selected.state, 'SUCCEEDED');
      } else assert.equal(requested.selected.state, 'SUCCEEDED');
      await exec(compose[0], [...compose.slice(1), 'restart', 'control-api'], { timeout: 30000 });
      await exec(
        compose[0],
        [
          ...compose.slice(1),
          'up',
          '-d',
          '--wait',
          '--no-deps',
          '--no-build',
          '--pull',
          'never',
          'control-api',
        ],
        { timeout: 30000 },
      );
      await expect
        .poll(async () => (await readStatus(true, true))?.selected.state, {
          timeout: 10000,
          intervals: [250, 500, 1000],
        })
        .toBe('SUCCEEDED');
      const retrieving = maker.waitForResponse(
        (response) => new URL(response.url()).searchParams.get('artifact') === '1',
      );
      await maker.getByRole('button', { name: 'Retrieve verified export', exact: true }).click();
      const retrieved = await retrieving;
      assert.equal(retrieved.status(), 200);
      const downloaded = (await retrieved.json()).download;
      evidenceExportDownload.parse(downloaded);
      assert.equal(downloaded.outputDigest, sha256(downloaded.artifact));
      assert.equal(JSON.stringify(downloaded).includes('receiptBase64'), false);
      assert.equal(JSON.stringify(downloaded).includes('capsule_digest'), false);
      assert.equal(JSON.stringify(downloaded).includes('ciphertext_and_tag'), false);
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
      await maker.screenshot({ path: join(artifacts, 'rpc-desktop.png'), fullPage: true });
      await maker.setViewportSize({ width: 360, height: 900 });
      assert.equal(
        await maker.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
        true,
      );
      await maker.screenshot({ path: join(artifacts, 'rpc-reflow.png'), fullPage: true });
    },
  );
  await withTransactionBrowser(
    {
      secretRoot,
      evidenceRoot: actorRoot,
      artifacts: join(artifacts, 'foreign-privacy'),
      route: '/operate/evidence',
      privacyDomainId: foreignPrivacy,
    },
    async ({ maker }) => {
      const api = await publicEvidenceReader(maker, secretRoot, participantId, foreignPrivacy);
      for (const path of [
        `evidence-records/urn:openpc:resource:${selectedId}`,
        `evidence-records/urn:openpc:resource:${selectedId}/export-range`,
        `evidence-exports/${exportRef}`,
      ]) {
        const denied = await api(path);
        assert.equal(denied.status, 404);
        assert.equal(JSON.stringify(denied.body).includes(selectedId), false);
        assert.equal(JSON.stringify(denied.body).includes(scope.streamId), false);
      }
      const region = maker.getByRole('region', { name: 'Evidence catalogue' });
      assert.equal((await region.innerText()).includes(records[0].receiptDigest), false);
    },
  );
  process.stdout.write(
    `OPENPC_RPC_BROWSER|PASS|public-catalogue|minimized-export|approval-step-up|lost-response|restart|foreign-participant|same-participant-foreign-privacy|unsupported-deletion|keyboard|axe|reflow|artifacts=${artifacts}\n`,
  );
}
