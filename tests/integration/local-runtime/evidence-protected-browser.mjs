import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdir, readFile, writeFile, access } from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { Pool } from 'pg';
import { expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import {
  governThroughWorkbench,
  withTransactionBrowser,
} from './transaction-workbench-browser.mjs';
import { publicEvidenceReader } from './evidence-rejection-deletion-checks.mjs';
import { sha256 } from '../../../services/control-api/src/configuration/digest.ts';
import { uuidv7 } from '../../../services/control-api/src/configuration/governed-mutation-http.ts';
const exec = promisify(execFile);
const [secretRoot, evidenceRoot, dataRoot, composeJson, participantId, privacyDomainId] =
  process.argv.slice(2);
assert.ok(
  secretRoot && evidenceRoot && dataRoot && composeJson && participantId && privacyDomainId,
);
await exec('bash', [
  'scripts/maintenance/run-bounded.sh',
  '--profile',
  'runtime-target',
  '--reuse',
  '--',
  'true',
]);
const compose = JSON.parse(composeJson);
assert.equal(compose[0], 'docker');
assert.equal(compose[1], 'compose');
const command = (args) =>
  exec(compose[0], [...compose.slice(1), ...args], { timeout: 90000, maxBuffer: 1048576 });
const root = join(evidenceRoot, 'protected-proof-browser'),
  artifacts = join(root, new Date().toISOString().replaceAll(':', '-'));
await mkdir(artifacts, { recursive: true, mode: 0o700 });
if (
  !(await access(join(root, 'deployment-intent-actors.json')).then(
    () => true,
    (error) => {
      if (error.code !== 'ENOENT') throw error;
      return false;
    },
  ))
)
  await exec(
    process.execPath,
    [
      '--import',
      'tsx',
      'tests/integration/local-runtime/deployment-intent-actors.mjs',
      secretRoot,
      root,
      participantId,
      'bootstrap-evidence-protected',
      privacyDomainId,
      '018f0000-0000-7000-8000-000000000201',
    ],
    { timeout: 30000, maxBuffer: 65536 },
  );
const pool = new Pool({
  host: '127.0.0.1',
  port: 55432,
  database: 'openpc_control',
  user: 'openpc_control',
  password: (await readFile(join(secretRoot, 'control_pg_password.txt'), 'utf8')).trim(),
  max: 1,
});
const time = (offset) =>
  new Date(Date.now() + offset).toISOString().replace(/\.([0-9]{3})Z$/u, '.$1000Z');
const container = (await command(['ps', '-q', 'control-api'])).stdout.trim();
const image = JSON.parse(
  (await exec('docker', ['image', 'inspect', 'openpc-r1-dev/control-api:local'])).stdout,
)[0];
assert.equal(JSON.parse((await exec('docker', ['inspect', container])).stdout)[0].Image, image.Id);
const executable = join(artifacts, 'evidence-worker.mjs');
await exec('docker', ['cp', `${container}:/app/evidence-worker.mjs`, executable]);
const sourceRoot = join(dataRoot, `protected-source-${uuidv7()}`);
await mkdir(sourceRoot, { mode: 0o700 });
await writeFile(join(sourceRoot, 'encryption.key'), randomBytes(32), { mode: 0o600, flag: 'wx' });
const streamId = `protected-authentication-${uuidv7()}`,
  configuration = join(artifacts, 'worker-config.json');
await writeFile(
  configuration,
  JSON.stringify({
    database: {
      host: '127.0.0.1',
      port: 55432,
      database: 'openpc_control',
      user: 'openpc_local_control_worker',
      passwordFile: join(secretRoot, 'control_worker_runtime_db_password.txt'),
    },
    vaultDirectory: join(sourceRoot, 'vault'),
    sinkId: `protected-authentication-${uuidv7()}`,
    scopes: [
      {
        participantId,
        privacyDomainId,
        streamId,
        source: 'AUTHENTICATION',
        activeKeyId: 'source-test',
        keys: [{ keyId: 'source-test', keyFile: join(sourceRoot, 'encryption.key') }],
        retentionSeconds: 86400,
        capacityBytes: 1048576,
      },
    ],
  }),
  { mode: 0o600 },
);
const runWorker = () =>
  exec(process.execPath, [executable, '--once'], {
    env: { ...process.env, OPENPC_EVIDENCE_WORKER_CONFIG_FILE: configuration },
    timeout: 20000,
    maxBuffer: 65536,
  });
const endpoint = '/api/v1/ui/protected-proof-workbench';
try {
  await withTransactionBrowser(
    {
      secretRoot,
      evidenceRoot: root,
      artifacts,
      route: '/operate/evidence',
      privacyDomainId,
      reuseSessions: true,
    },
    async ({ maker, checker, actors }) => {
      // Context entry is recorded in the former Platform context. Produce the
      // source through real browser WebAuthn in the selected Participant context.
      await maker.evaluate(
        async ({ participantId, privacyDomainId }) => {
          const encode = (value) =>
            btoa(String.fromCharCode(...new Uint8Array(value)))
              .replaceAll('+', '-')
              .replaceAll('/', '_')
              .replace(/=+$/u, '');
          const decode = (value) =>
            Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/')), (c) =>
              c.charCodeAt(0),
            );
          const digest = new Uint8Array(
            await crypto.subtle.digest(
              'SHA-256',
              new TextEncoder().encode(JSON.stringify({ participantId, privacyDomainId })),
            ),
          );
          const binding = {
            actionIntentId: 'ACT-IDENTITY_CREATE_SESSION-V1',
            actionIntentDigest:
              'sha256:dbc8290dd60814d5bb4248fefc9550f43d0dc97d6333ac232c8ab8a98c3354d2',
            resourceId: participantId,
            resourceDigest:
              'sha256:' + Array.from(digest, (b) => b.toString(16).padStart(2, '0')).join(''),
          };
          const post = async (path, body) => {
            const response = await fetch('/api/v1/ui/webauthn/assertion/' + path, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(body),
            });
            if (!response.ok)
              throw new Error('Authentication source ' + path + ' denied: ' + response.status);
            return response.json();
          };
          const challenge = await post('challenge', binding),
            options = challenge.publicKey;
          const credential = await navigator.credentials.get({
            publicKey: {
              ...options,
              challenge: decode(options.challenge),
              allowCredentials: options.allowCredentials.map((c) => ({ ...c, id: decode(c.id) })),
            },
          });
          if (!(credential instanceof PublicKeyCredential))
            throw new Error('Authentication source credential unavailable');
          const assertion = credential.response;
          await post('verify', {
            ...binding,
            challenge: options.challenge,
            assertion: {
              credentialId: encode(credential.rawId),
              authenticatorData: encode(assertion.authenticatorData),
              clientDataJson: encode(assertion.clientDataJSON),
              signature: encode(assertion.signature),
            },
          });
        },
        { participantId, privacyDomainId },
      );
      let selected;
      for (let batch = 0; batch < 64; batch++) {
        await runWorker();
        selected = (
          await pool.query(
            `select c.evidence_id::text id,a.occurrence_id::text occurrence_id,a.operation_id::text operation_id
    from control.evidence_catalogue c join control.authentication_occurrence a on a.occurrence_id::text=c.record_id
    where c.participant_id=$1 and c.privacy_domain_id=$2 and c.stream_id=$3 and a.method='WEBAUTHN_ASSERTION'
    and a.principal_id=$4 order by c.sequence desc limit 1`,
            [participantId, privacyDomainId, streamId, actors.maker.principalId],
          )
        ).rows[0];
        if (selected) break;
      }
      assert.ok(selected, 'actual browser WebAuthn occurrence must reach source custody');
      const api = await publicEvidenceReader(maker, secretRoot, participantId, privacyDomainId);
      const source = await api(
        `evidence-records/urn:openpc:resource:${selected.id}/protected-proof-source`,
      );
      assert.equal(source.status, 200);
      assert.equal(source.body.operationId, selected.operation_id);
      assert.equal(source.body.materialType, 'IDENTITY_SIGNED_AUTHORIZATION_ASSERTION');
      const retained = await governThroughWorkbench({
        maker,
        checker,
        checkerId: actors.checker.principalId,
        label: 'Retain a protected Identity proof',
        fields: {
          'Authentication evidence reference': `urn:openpc:resource:${selected.id}`,
          'Protected retention purpose': 'Review a committed authentication',
          'Case reference': `case-${selected.id}`,
          'Retain until (UTC, six fractional digits)': time(86400000),
        },
        reason: 'Preserve this exact authentication proof for the named case.',
      });
      assert.deepEqual(retained.review.candidate.candidate.source, source.body);
      assert.equal(JSON.stringify(retained.review).includes('assertionBase64'), false);
      const object = retained.completed.result;
      assert.equal(object.objectVersion, '1');
      const grant = async (suffix) =>
        governThroughWorkbench({
          maker,
          checker,
          checkerId: actors.checker.principalId,
          label: 'Request protected proof access',
          fields: {
            'Protected object reference': object.objectRef,
            'Protected access purpose': 'Review a committed authentication',
            'Case reference': `case-${suffix}-${selected.id}`,
            'Access expires at (UTC, within five minutes)': time(240000),
          },
          reason: 'Approve one exact sender-bound protected proof delivery.',
        });
      const granted = await grant('positive');
      assert.equal(granted.completed.result.recipientPrincipalId, actors.maker.principalId);
      assert.equal(granted.completed.result.state, 'AVAILABLE');
      const read = async (page, ref) => {
        await page.getByLabel('Protected access reference', { exact: true }).fill(ref);
        const pending = page.waitForResponse(
          (r) => new URL(r.url()).pathname === endpoint && r.request().method() === 'GET',
        );
        await page.getByRole('button', { name: 'Read protected access', exact: true }).click();
        const result = await pending;
        assert.equal(result.status(), 200);
        return result.json();
      };
      const view = await read(maker, granted.completed.result.accessRef);
      assert.equal(view.access.object.objectDigest, object.objectDigest);
      await read(checker, view.access.accessRef);
      const forbidden = await checker.evaluate(
        async ({ endpoint, input }) => {
          const r = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(input),
          });
          return { status: r.status, body: await r.json() };
        },
        {
          endpoint,
          input: {
            accessId: view.access.accessRef.slice(-36),
            actorKey: view.actorKey,
            accessDigest: view.accessDigest,
            requestKey: uuidv7(),
          },
        },
      );
      assert.equal(forbidden.status, 404);
      assert.equal(JSON.stringify(forbidden.body).includes('assertionBase64'), false);
      await maker.bringToFront();
      await read(maker, view.access.accessRef);
      const downloadPromise = maker.waitForEvent('download');
      await maker
        .getByRole('button', { name: 'Consume once and download proof', exact: true })
        .click();
      const download = await downloadPromise,
        stream = await download.createReadStream(),
        chunks = [];
      for await (const chunk of stream) chunks.push(chunk);
      const bytes = Buffer.concat(chunks),
        disclosed = JSON.parse(bytes.toString());
      assert.equal(sha256(disclosed), object.objectDigest);
      assert.deepEqual(disclosed.source, source.body);
      bytes.fill(0);
      const consumed = await read(maker, view.access.accessRef);
      assert.equal(consumed.access.state, 'CONSUMED');
      await expect(
        maker.getByRole('button', { name: 'Consume once and download proof', exact: true }),
      ).toBeDisabled();
      const lost = await grant('lost-response'),
        lostRef = lost.completed.result.accessRef;
      await read(maker, lostRef);
      let intercepted = false;
      const lose = async (route) => {
        if (route.request().method() !== 'POST') return route.continue();
        const actual = await route.fetch();
        assert.equal(actual.status(), 202);
        intercepted = true;
        await route.abort();
      };
      await maker.route(`**${endpoint}`, lose);
      await maker
        .getByRole('button', { name: 'Consume once and download proof', exact: true })
        .click();
      await expect(maker.getByRole('region', { name: 'Protected proof delivery' })).toContainText(
        'reconcile',
      );
      assert.equal(intercepted, true);
      await maker.unroute(`**${endpoint}`, lose);
      await command(['restart', 'control-api']);
      await command([
        'up',
        '-d',
        '--wait',
        '--no-deps',
        '--no-build',
        '--pull',
        'never',
        'control-api',
      ]);
      await maker.reload();
      const recovered = await read(maker, lostRef);
      assert.equal(recovered.access.state, 'CONSUMED');
      assert.ok(recovered.access.consumptionOperationId);
      const publicObject = await api(`protected-proofs/${object.objectRef}`);
      assert.equal(publicObject.status, 200);
      assert.deepEqual(publicObject.body, object);
      for (const context of [
        { participantId: uuidv7() },
        { privacyDomainId: '018f0000-0000-7000-8000-000000000201' },
      ]) {
        if (context.privacyDomainId === privacyDomainId) continue;
        const denied = await api(`protected-proofs/${object.objectRef}`, context);
        assert.ok(denied.status >= 400);
        assert.equal(JSON.stringify(denied.body).includes(object.objectDigest), false);
      }
      const catalogue = await api(`evidence-records/urn:openpc:resource:${selected.id}`);
      assert.equal(catalogue.status, 200);
      assert.equal(JSON.stringify(catalogue.body).includes('assertionBase64'), false);
      await maker.getByRole('button', { name: 'Read protected access', exact: true }).focus();
      await maker.keyboard.press('Enter');
      await expect(maker.getByRole('region', { name: 'Protected proof delivery' })).toContainText(
        'CONSUMED',
      );
      assert.deepEqual((await new AxeBuilder({ page: maker }).analyze()).violations, []);
      await maker.screenshot({ path: join(artifacts, 'protected-desktop.png'), fullPage: true });
      await maker.setViewportSize({ width: 360, height: 880 });
      assert.equal(
        await maker.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
        true,
      );
      assert.deepEqual((await new AxeBuilder({ page: maker }).analyze()).violations, []);
      await maker.screenshot({ path: join(artifacts, 'protected-reflow.png'), fullPage: true });
      process.stdout.write(
        'OPENPC_PROTECTED_PROOF_BROWSER|PASS|actual-authentication-source|independent-approval|fresh-step-up|exact-version|sender-bound-one-use|lost-response|restart|privacy|keyboard|axe|reflow\n',
      );
    },
  );
} finally {
  await pool.end();
}
