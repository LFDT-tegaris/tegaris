import { openPolicySimulation } from './evaluation-ui-browser.mjs';
import { activateFirstPolicy } from './first-policy-activation-browser.mjs';
import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import AxeBuilder from '@axe-core/playwright';
import { expect } from '@playwright/test';
import { withTransactionBrowser } from './transaction-workbench-browser.mjs';
import {
  command,
  loadReferences,
  policyReferenceForm,
} from './policy-release-browser-commands.mjs';
import { simulateSourcePolicy } from './policy-source-browser.mjs';
import { responseIds } from '../../../apps/admin-web/app/api/v1/ui/local-runtime.ts';

export async function releaseFirstPolicy({
  secretRoot,
  evidenceRoot,
  inputPath,
  journey = 'first-policy',
  browser,
  onRuntimeActivated,
  historicalReadbackOnly = false,
}) {
  await promisify(execFile)('bash', [
    'scripts/maintenance/run-bounded.sh',
    '--profile',
    'runtime-target',
    '--reuse',
    '--',
    'true',
  ]);
  assert.ok(secretRoot && evidenceRoot && inputPath);
  assert.equal(typeof historicalReadbackOnly, 'boolean');
  if (historicalReadbackOnly) assert.equal(process.env.OPENPC_FIRST_POLICY_ACTIVATE, '1');
  assert.ok(
    journey === 'first-policy' ||
      /^rpc-policy(?:-[2-9][0-9]*)?$/u.test(journey) ||
      /^rpc-source(?:-[2-9][0-9]*)?-policy$/u.test(journey),
  );
  const rpcJourney = /^rpc-policy(?:-[2-9][0-9]*)?$/u.test(journey);
  const read = async (path) => JSON.parse(await readFile(path, 'utf8'));
  const input = await read(inputPath);
  const authored = await read(
    join(
      evidenceRoot,
      journey === 'first-policy' ? 'policy-set-result.json' : `${journey}-result.json`,
    ),
  );
  const checkpointPath = join(evidenceRoot, `${journey}-release-checkpoint.json`);
  const checkpoint = await read(checkpointPath).catch((error) => {
    if (error.code !== 'ENOENT') throw error;
    return { references: {} };
  });
  if (historicalReadbackOnly) {
    for (const name of ['approvalId', 'releaseId', 'occurrenceId'])
      assert.match(
        checkpoint.references?.[name] ?? '',
        /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
        `Original ${name} required`,
      );
    assert.ok(checkpoint.simulation, 'Original source simulation required');
  }
  const artifacts = join(
    evidenceRoot,
    journey === 'first-policy' ? 'first-policy-browser' : `${journey}-release-browser`,
    new Date().toISOString().replaceAll(':', '-'),
  );
  await mkdir(artifacts, { recursive: true, mode: 0o700 });
  const endpoint = '/api/v1/ui/policy-release-workbench';
  const storageKey = 'openpc:policy-release-workflow:v2';
  const withBrowser = browser ? async (_options, run) => run(browser) : withTransactionBrowser;
  await withBrowser(
    {
      secretRoot,
      evidenceRoot,
      artifacts,
      privacyDomainId: input.privacyDomainId,
      reuseSessions: true,
    },
    async ({ maker, checker, actors }) => {
      const publicRead = async (path) => {
        const ids = responseIds();
        const response = await fetch(`http://127.0.0.1:8080${path}`, {
          headers: {
            'Cookie': `__Host-openpc_session=${actors.maker.sessionToken}`,
            'OpenPC-API-Version': '1',
            'OpenPC-Participant-ID': `urn:openpc:participant:${input.participantId}`,
            'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${input.privacyDomainId}`,
            'X-Request-ID': ids.requestId,
            'X-Correlation-ID': ids.correlationId,
          },
        });
        assert.equal(response.status, 200, `public read ${path}`);
        return response.json();
      };
      const version = await publicRead(
        `/api/v1/policy-versions/urn:openpc:policy-version:${authored.versionId}`,
      );
      assert.equal(version.policySetId, authored.policySetId);
      assert.equal(version.normalizedPolicyDigest, input.semanticDigest);
      if (!checkpoint.simulation) {
        const parent = await publicRead(`/api/v1/policy-sets/${authored.policySetId}`);
        assert.equal(parent.state, input.predecessorDigest ? 'ACTIVE' : 'DRAFT');
        assert.equal(parent.activeVersionDigest, input.predecessorDigest ?? null);
        await maker.goto('http://localhost:8080/configure/policies');
        await expect(
          maker.getByLabel('Policy set for this version', { exact: true }),
        ).toBeVisible();
        await maker
          .getByLabel('Policy set for this version', { exact: true })
          .selectOption(authored.policySetId);
        await openPolicySimulation(maker);
        checkpoint.simulation = await simulateSourcePolicy(
          maker,
          input.sourceRequest,
          authored.versionId,
        );
        await writeFile(checkpointPath, JSON.stringify(checkpoint), { mode: 0o600 });
        await maker.screenshot({ path: join(artifacts, 'source-simulation.png'), fullPage: true });
      }
      if (checkpoint.storage)
        await maker.evaluate(({ key, value }) => localStorage.setItem(key, value), {
          key: storageKey,
          value: checkpoint.storage,
        });
      await maker.goto('http://localhost:8080/govern/policy-releases');
      await maker.getByRole('combobox', { name: /^Workflow/u }).selectOption('PREPARE');
      await checker.goto('http://localhost:8080/govern/policy-releases');
      await checker.getByRole('combobox', { name: /^Workflow/u }).selectOption('REVIEW');
      const persist = async () => {
        await expect
          .poll(async () => {
            const stored = await maker.evaluate((key) => localStorage.getItem(key), storageKey);
            return (
              !!stored && Object.values(checkpoint.references).every((id) => stored.includes(id))
            );
          })
          .toBe(true);
        checkpoint.storage = await maker.evaluate((key) => localStorage.getItem(key), storageKey);
        await writeFile(checkpointPath, JSON.stringify(checkpoint), { mode: 0o600 });
      };
      const refs = checkpoint.references;
      if (refs.occurrenceId) {
        // Session-bound draft storage is deliberately discarded after login.
        // Completed authority resumes through supported public reference reads.
        await maker.getByRole('combobox', { name: /^Workflow/u }).selectOption('REVIEW');
        await loadReferences(maker, refs);
      }
      if (!refs.approvalId) {
        for (const [label, value] of [
          ['Policy version ID', authored.versionId],
          ['Policy artifact digest', version.normalizedPolicyDigest],
          ['Dependency closure digest', version.dependencyClosureDigest],
          ['Checker principal ID', actors.checker.principalId],
          [
            'Business reason',
            input.predecessorDigest
              ? 'Release the governed RPC successor while preserving the original source policy history.'
              : 'Release the original publicly authored source policy through independent approval.',
          ],
        ])
          await maker.getByLabel(label, { exact: true }).fill(value);
        await command(maker, 'Review release details', 'PREVIEW');
        await maker.getByRole('heading', { name: 'Release review', exact: true }).waitFor();
        await persist();
        const operation = await command(maker, 'Request checker approval', 'SUBMIT_APPROVAL');
        refs.approvalId = operation.resourceRef.split(':').at(-1);
        checkpoint.approvalOperation = operation;
        await persist();
      }
      await loadReferences(checker, refs);
      let approval = await publicRead(
        `/api/v1/approval-requests/urn:openpc:resource:${refs.approvalId}`,
      );
      assert.equal(approval.makerSubjectRef, `urn:openpc:resource:${actors.maker.principalId}`);
      assert.equal(approval.checkerSubjectRef, `urn:openpc:resource:${actors.checker.principalId}`);
      if (historicalReadbackOnly) assert.equal(approval.state, 'APPROVED');
      if (approval.state === 'REQUESTED') {
        const denied = await maker.evaluate(
          async ({ endpoint, approvalId }) => {
            const response = await fetch(endpoint, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ command: 'APPROVE', approvalId }),
            });
            return response.status;
          },
          { endpoint, approvalId: refs.approvalId },
        );
        assert.ok([403, 404].includes(denied), `maker self approval must be denied: ${denied}`);
        await command(checker, 'Approve with security key', 'APPROVE');
        approval = await publicRead(
          `/api/v1/approval-requests/urn:openpc:resource:${refs.approvalId}`,
        );
      }
      assert.equal(approval.state, 'APPROVED');
      if (!refs.occurrenceId) {
        await maker.getByRole('button', { name: 'Refresh policy workflow', exact: true }).click();
        await maker.getByText('APPROVED', { exact: true }).waitFor();
      }
      if (!refs.releaseId) {
        const operation = await command(maker, 'Create approved release', 'CREATE_RELEASE');
        refs.releaseId = operation.resourceRef.split(':').at(-1);
        checkpoint.releaseOperation = operation;
        await persist();
      }
      await loadReferences(checker, refs);
      let release = await publicRead(
        `/api/v1/release-bundles/urn:openpc:resource:${refs.releaseId}`,
      );
      if (historicalReadbackOnly) assert.ok(['PUBLISHED', 'ACTIVE'].includes(release.state));
      if (release.state === 'DRAFT') {
        await command(checker, 'Publish with security key', 'PUBLISH');
        release = await publicRead(`/api/v1/release-bundles/urn:openpc:resource:${refs.releaseId}`);
      }
      assert.ok(
        (refs.occurrenceId ? ['PUBLISHED', 'ACTIVE'] : ['PUBLISHED']).includes(release.state),
        `release must match its actual lifecycle: ${release.state}`,
      );
      assert.equal(release.manifestDigest, input.semanticDigest);
      assert.equal(release.dependencyClosureDigest, version.dependencyClosureDigest);
      const parent = await publicRead(`/api/v1/policy-sets/${authored.policySetId}`);
      if (!refs.occurrenceId) {
        assert.equal(parent.state, input.predecessorDigest ? 'ACTIVE' : 'DRAFT');
        assert.equal(parent.activeVersionDigest, input.predecessorDigest ?? null);
      }
      await checker.reload();
      await checker
        .getByRole('article')
        .filter({ has: checker.getByRole('heading', { name: 'Release', exact: true }) })
        .getByText(release.state, { exact: true })
        .waitFor();
      const inspectRelease = async () => {
        for (const width of [1440, 360]) {
          await checker.setViewportSize({ width, height: 1000 });
          await expect(checker.getByRole('combobox', { name: /^Workflow/u })).toBeVisible();
          await policyReferenceForm(checker).getByLabel('Approval ID', { exact: true }).focus();
          await checker.keyboard.press('Tab');
          await expect(
            policyReferenceForm(checker).getByLabel('Release ID', { exact: true }),
          ).toBeFocused();
          assert.equal(
            await checker.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
            true,
          );
          const axe = await new AxeBuilder({ page: checker })
            .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'])
            .analyze();
          assert.deepEqual(
            axe.violations.map((v) => ({ id: v.id, targets: v.nodes.map((n) => n.target) })),
            [],
          );
          await checker.screenshot({
            path: join(artifacts, `policy-release-${width}.png`),
            fullPage: true,
          });
        }
      };
      if (!rpcJourney) await inspectRelease();
      if (process.env.OPENPC_FIRST_POLICY_ACTIVATE === '1') {
        await activateFirstPolicy({
          maker,
          checker,
          input,
          authored,
          checkpoint,
          publicRead,
          persist,
          evidenceRoot,
          secretRoot,
          journey,
          historicalReadbackOnly,
          onActivated:
            rpcJourney && !historicalReadbackOnly
              ? async ({ discovery, compose, ownerRoot }) => {
                  if (onRuntimeActivated) {
                    await onRuntimeActivated({ discovery, compose, ownerRoot });
                    checkpoint.rpcCustodyPassed = true;
                    await persist();
                    return;
                  }
                  await new Promise((resolve, reject) => {
                    const child = spawn(
                      process.execPath,
                      [
                        '--import',
                        'tsx',
                        'tests/integration/local-runtime/evidence-rpc-custody.mjs',
                        secretRoot,
                        input.participantId,
                        input.privacyDomainId,
                        discovery.targetId,
                        JSON.stringify(compose),
                        join(ownerRoot, 'data/runtime-bootstrap'),
                      ],
                      { stdio: 'inherit' },
                    );
                    child.once('error', reject);
                    child.once('exit', (code, signal) => {
                      if (code === 0) resolve();
                      else reject(new Error(`RPC custody failed: exit=${code}, signal=${signal}`));
                    });
                  });
                  checkpoint.rpcCustodyPassed = true;
                  await persist();
                }
              : undefined,
        });
        if (rpcJourney) await inspectRelease();
        for (const width of [1440, 360]) {
          await checker.setViewportSize({ width, height: 1000 });
          assert.equal(
            await checker.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
            true,
          );
          const axe = await new AxeBuilder({ page: checker })
            .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'])
            .analyze();
          assert.deepEqual(
            axe.violations.map((v) => ({ id: v.id, targets: v.nodes.map((n) => n.target) })),
            [],
          );
          await checker.screenshot({
            path: join(artifacts, `policy-active-${width}.png`),
            fullPage: true,
          });
        }
      }
      checkpoint.version = version;
      checkpoint.published = release;
      checkpoint.artifacts = artifacts;
      await persist();
      process.stdout.write(
        historicalReadbackOnly
          ? `OPENPC_FIRST_POLICY_BROWSER|PASS|original-activation-readback-only|approved-release|active-matched|restart|reload|keyboard|axe|360px|custody-independent\n`
          : `OPENPC_FIRST_POLICY_BROWSER|PASS|source-allow-deny|explicit-checker|maker-denial|approval|fresh-WebAuthn|published|${checkpoint.activeOccurrence ? 'active-matched' : 'no-activation'}|reload|keyboard|axe|360px\n`,
      );
    },
  );
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [secretRoot, evidenceRoot, inputPath, journey = 'first-policy', mode] =
    process.argv.slice(2);
  assert.ok(mode === undefined || mode === '--historical-readback');
  await releaseFirstPolicy({
    secretRoot,
    evidenceRoot,
    inputPath,
    journey,
    historicalReadbackOnly: mode === '--historical-readback',
  });
}
