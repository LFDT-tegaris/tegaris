import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { isDeepStrictEqual, promisify } from 'node:util';

// These assertions also run in the small driver contract suite. The integrated
// callers supply real BFF replies and authoritative SQL snapshots, never seeded effects.
export function assertEndpointDenial({ status, problem, before, after, expectedStatus, code }) {
  assert.equal(status, expectedStatus, 'Expected the specific owner denial');
  assert.equal(problem.code, code);
  assert.equal(problem.status, expectedStatus);
  for (const key of Object.keys(problem))
    assert.ok(
      ['type', 'title', 'status', 'code', 'truthState', 'retryable', 'traceId'].includes(key),
      'Denial exposed an unexpected field',
    );
  assert.equal(problem.truthState, expectedStatus === 412 ? 'STALE' : 'DENIED');
  assert.deepEqual(
    after,
    before,
    'Denied endpoint request changed durable state or signed effects',
  );
}
export function assertEndpointReplay({ request, status, result, original, before, after }) {
  assert.equal(status, 202);
  assert.deepEqual(request, original.request, 'Recovery must preserve every original input');
  assert.deepEqual(result, original.result, 'Recovery must return the exact original operation');
  assert.deepEqual(after, before, 'Duplicate recovery must not add endpoint or signed effects');
}

export function endpointAlternateContext(session, participantId, privacyDomainId) {
  assert.equal(session.authenticated, true);
  assert.equal(session.contextMode, 'PARTICIPANT');
  assert.equal(session.participantId, participantId);
  assert.equal(session.privacyDomainId, privacyDomainId);
  assert.ok(typeof session.sessionId === 'string' && typeof session.principalId === 'string');
  assert.ok(Array.isArray(session.availableContexts));
  const seen = new Set();
  for (const item of session.availableContexts) {
    for (const key of ['participantId', 'privacyDomainId'])
      assert.match(
        item[key],
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
      );
    assert.ok(!seen.has(item.privacyDomainId), 'Ambiguous advertised context');
    seen.add(item.privacyDomainId);
  }
  return session.availableContexts.find(
    (item) => item.participantId === participantId && item.privacyDomainId !== privacyDomainId,
  );
}
export function requireEndpointMutationContext(
  session,
  participantId,
  privacyDomainId,
  mode = 'first-mutation-context',
) {
  assert.ok(
    ['first-mutation-context', 'replay-logout'].includes(mode),
    'Unknown endpoint in-flight acceptance mode',
  );
  if (mode === 'replay-logout') return undefined;
  const alternate = endpointAlternateContext(session, participantId, privacyDomainId);
  assert.ok(
    alternate,
    'BLOCKED_NOTIFICATION_ENDPOINT_FIRST_CONTEXT: advertised alternate context required before CREATE/UPDATE',
  );
  return alternate;
}

export function requireRetainedEndpointContext(
  proof,
  operationId,
  mode = 'first-mutation-context',
) {
  if (proof)
    assert.equal(
      proof.operationId,
      operationId,
      'Retained context proof belongs to another original',
    );
  if (mode === 'replay-logout') return;
  assert.equal(mode, 'first-mutation-context');
  assert.ok(
    proof?.state === 'PASS' && proof.firstMutation === true && proof.mountedBeforeAndAfter === true,
    'BLOCKED_NOTIFICATION_ENDPOINT_FIRST_CONTEXT: retained original lacks passing first-response context evidence; readback cannot recreate it',
  );
}

/** Return an already authenticated actor through the existing context selector.
 * This owner rotates context with real step-up; it never starts another login or
 * sends another endpoint mutation. The caller separately reads the original ID. */
export async function restoreEndpointBrowserContext({
  page,
  origin,
  participantId,
  privacyDomainId,
  originalSession,
}) {
  const currentReply = await page.request.get(`${origin}/api/v1/ui/local-session`);
  assert.equal(currentReply.status(), 200);
  const current = await currentReply.json();
  endpointAlternateContext(current, participantId, current.privacyDomainId);
  assert.equal(current.principalId, originalSession.principalId);
  assert.notEqual(current.privacyDomainId, privacyDomainId);
  assert.ok(
    current.availableContexts.some(
      (context) =>
        context.participantId === participantId && context.privacyDomainId === privacyDomainId,
    ),
    'BLOCKED_NOTIFICATION_ENDPOINT_RETURN_CONTEXT: original context is not advertised',
  );
  await page
    .getByRole('combobox', { name: 'Organization workspace', exact: true })
    .selectOption(privacyDomainId);
  const ownerPath = '/api/v1/ui/session/context';
  let returned, ownerFailure;
  // Capture the genuine owner body before forwarding it: the UI reloads as
  // soon as it receives this response, which can evict Playwright's body handle.
  const capture = async (route) => {
    if (route.request().method() !== 'POST') return route.continue();
    try {
      const response = await route.fetch();
      returned = await response.json();
      await route.fulfill({ response });
    } catch (error) {
      ownerFailure = error;
      await route.abort('failed').catch(() => {});
    }
  };
  await page.route(`**${ownerPath}`, capture);
  let response;
  try {
    const reply = page.waitForResponse(
      (value) => value.request().method() === 'POST' && new URL(value.url()).pathname === ownerPath,
    );
    const loaded = page.waitForEvent('load');
    void reply.catch(() => {});
    void loaded.catch(() => {});
    [response] = await Promise.all([
      reply,
      loaded,
      page
        .getByRole('button', {
          name: 'Verify and enter workspace',
          exact: true,
        })
        .click(),
    ]);
    if (ownerFailure) throw ownerFailure;
  } finally {
    await page.unroute(`**${ownerPath}`, capture);
  }
  assert.equal(response.status(), 201);
  assert.deepEqual(response.request().postDataJSON(), {
    participantId,
    privacyDomainId,
    expectedSessionId: current.sessionId,
  });
  assert.equal(returned.participantId, participantId);
  assert.equal(returned.privacyDomainId, privacyDomainId);
  assert.equal(returned.contextMode, 'PARTICIPANT');
  assert.notEqual(returned.sessionId, current.sessionId);
  const readback = await page.request.get(`${origin}/api/v1/ui/local-session`);
  assert.equal(readback.status(), 200);
  const restored = await readback.json();
  endpointAlternateContext(restored, participantId, privacyDomainId);
  assert.equal(restored.principalId, originalSession.principalId);
  assert.equal(restored.sessionId, returned.sessionId);
  assert.notEqual(restored.sessionId, originalSession.sessionId);
  return restored;
}

export function assertEndpointFirstCommit(before, after, original) {
  const operation = original.result.operation;
  assert.equal(original.status, 202);
  assert.ok(['CREATE', 'UPDATE'].includes(original.request.command));
  assert.equal(operation.state, 'SUCCEEDED');
  assert.equal(operation.truthState, 'SUCCESS');
  const endpointId = operation.resourceRef.slice(-36);
  for (const [collection, key] of [
    ['operations', 'operation_id'],
    ['receipts', 'operation_id'],
    ['events', 'correlation_id'],
  ]) {
    const added = after[collection].filter((row) => row[key] === operation.operationId);
    assert.equal(added.length, 1, `First mutation must have exactly one ${collection} entry`);
    assert.deepEqual(
      after[collection].filter((row) => row[key] !== operation.operationId),
      before[collection],
    );
  }
  assert.deepEqual(after.attempts, before.attempts, 'CREATE/UPDATE must not send a verification');
  const old = before.endpoints.filter((row) => row.endpoint_id === endpointId);
  const current = after.endpoints.filter((row) => row.endpoint_id === endpointId);
  assert.equal(old.length, original.request.command === 'CREATE' ? 0 : 1);
  assert.equal(current.length, 1);
  assert.equal(String(current[0].revision), operation.revision);
  assert.equal(
    operation.revision,
    original.request.command === 'CREATE' ? '1' : String(BigInt(old[0].revision) + 1n),
  );
  assert.equal(current[0].state, old[0]?.state === 'QUARANTINED' ? 'QUARANTINED' : 'DISABLED');
  assert.deepEqual(
    after.endpoints.filter((row) => row.endpoint_id !== endpointId),
    before.endpoints.filter((row) => row.endpoint_id !== endpointId),
  );
}

export const endpointEffectQueries = Object.freeze({
  endpoints: `select * from control.notification_endpoint where participant_id=$1 and privacy_domain_id=$2 order by endpoint_id`,
  operations: `select * from control.idempotency_record where participant_id=$1 and privacy_domain_id=$2 and action_intent_id=any($3::text[]) order by operation_id`,
  attempts: `select attempt_id,state,attached_operation_id,challenge_bytes,response_bytes,receipt_digest from control.notification_verification_attempt where participant_id=$1 and privacy_domain_id=$2 order by attempt_id`,
  receipts: `select * from control.audit_occurrence where participant_id=$1 and privacy_domain_id=$2 and aggregate_type='notification-endpoint' order by operation_id`,
  events: `select event_id,receipt_id,correlation_id,business_sequence,payload_cbor from control.outbox_event where participant_id=$1 and privacy_domain_id=$2 and aggregate_type='notification-endpoint' order by event_id`,
});

// All metadata effects use the rendered BFF and real Identity/Control/signing
// owners. Only initial external identity and signing trust are bootstrapped.
export async function runNotificationBrowser({
  argv = process.argv.slice(2),
  notificationRuntime,
} = {}) {
  const endpointInflightMode =
    process.env.OPENPC_NOTIFICATION_ENDPOINT_INFLIGHT_MODE ?? 'first-mutation-context';
  assert.ok(
    ['first-mutation-context', 'replay-logout'].includes(endpointInflightMode),
    'Unknown endpoint in-flight acceptance mode',
  );
  const { notificationRuntimeVerificationStats, withNotificationRuntimeLostAck } =
    await import('./notification-runtime-bootstrap.mjs');
  const { expect } = await import('@playwright/test');
  const { default: AxeBuilder } = await import('@axe-core/playwright');
  const { Pool } = await import('pg');
  const { authenticate } = await import('./participant-workbench-browser.mjs');
  const { withTransactionBrowser } = await import('./transaction-workbench-browser.mjs');
  const { notificationCommand, notificationView } =
    await import('../../../apps/admin-web/lib/notification-workflow.ts');
  const {
    endpointCommand,
    endpointView,
    endpointRecord,
    endpointRequestKey,
    notificationEndpointWorkbench,
  } = await import('../../../apps/admin-web/lib/notification-endpoint-workflow.ts');
  const kernel = await import('../../../packages/security-kernel/src/index.ts');

  const exec = promisify(execFile);
  await exec('bash', [
    'scripts/maintenance/run-bounded.sh',
    '--profile',
    'runtime-target',
    '--reuse',
    '--',
    'true',
  ]);
  const [secretRoot, evidenceRoot, participantId, privacyDomainId, composeJson] = argv;
  const compose = JSON.parse(composeJson);
  assert.deepEqual(compose.slice(0, 2), ['docker', 'compose']);
  const restartBrowserServices = async () => {
    if (notificationRuntime !== undefined) {
      const { runNotificationPackagedCompose } =
        await import('./notification-packaged-browser.mjs');
      return runNotificationPackagedCompose({
        runRoot: dirname(evidenceRoot),
        composeArgv: compose,
        operation: 'RESTART_BROWSER_SERVICES',
      });
    }
    return exec(
      compose[0],
      [...compose.slice(1), 'restart', '--no-deps', 'control-api', 'admin-web'],
      { timeout: 90000, maxBuffer: 1024 * 1024 },
    );
  };
  const artifacts = join(evidenceRoot, 'notification-browser');
  await mkdir(artifacts, { recursive: true, mode: 0o700 });
  const retainedActors = await readFile(
    join(artifacts, 'deployment-intent-actors.json'),
    'utf8',
  ).catch((error) => {
    if (error.code === 'ENOENT') return null;
    throw error;
  });
  if (!retainedActors)
    await exec(
      process.execPath,
      [
        '--import',
        'tsx',
        'tests/integration/local-runtime/deployment-intent-actors.mjs',
        secretRoot,
        artifacts,
        participantId,
        'bootstrap-notifications',
      ],
      { timeout: 30000, maxBuffer: 65536 },
    );
  else {
    const actors = JSON.parse(retainedActors);
    for (const actor of Object.values(actors)) {
      assert.match(actor.principalId, /^018f0018-/u);
      assert.equal(actor.privacyDomainId, privacyDomainId);
    }
  }
  const endpoint = '/api/v1/ui/notification-workbench';
  const origin = 'http://localhost:8080';
  const pool = new Pool({
    host: '127.0.0.1',
    port: 55432,
    database: 'openpc_control',
    user: 'openpc_control',
    password: (await readFile(join(secretRoot, 'control_pg_password.txt'), 'utf8')).trim(),
    max: 1,
  });
  const save = (name, value) =>
    writeFile(join(artifacts, name), JSON.stringify(value), { mode: 0o600 });
  const response = (page, method = 'POST', view) => {
    if (method === 'GET') assert.ok(view, 'Read waits must name their expected view');
    const pending = page.waitForResponse((value) => {
      const url = new URL(value.url());
      return (
        url.pathname === endpoint &&
        value.request().method() === method &&
        (method !== 'GET' || url.searchParams.get('view') === view)
      );
    });
    // Preserve the first interaction failure while the response wait settles.
    // Awaiting pending still rejects; this only prevents an unhandled rejection
    // from terminating the process before the browser owner retains its trace.
    void pending.catch(() => {});
    return pending;
  };
  const current = async (page, parameters) => {
    const result = await page.request.get(
      `${origin}${endpoint}?${new URLSearchParams(parameters)}`,
    );
    assert.equal(result.status(), 200);
    assert.equal(result.headers()['cache-control'], 'no-store');
    return result.json();
  };
  async function inspect(page, messageKey) {
    const pending = response(page, 'GET', 'DETAIL');
    await page.getByRole('button', { name: `Inspect ${messageKey}`, exact: true }).click();
    const result = await pending;
    assert.equal(result.status(), 200);
    const detail = await result.json();
    assert.equal(detail.kind, 'DETAIL');
    await expect(
      page.getByRole('heading', { name: 'Notification details', exact: true }),
    ).toBeFocused();
    return detail;
  }

  async function readKnownOperation(page, retained) {
    const request = notificationCommand.parse(retained.request);
    const original = notificationView.parse(retained.result);
    assert.equal(original.kind, 'OPERATION');
    assert.equal(original.actorKey, request.actorKey);
    assert.deepEqual(original.actor, { participantId, privacyDomainId });
    assert.equal(original.operation.idempotencyKey, `workbench-notification-${request.requestKey}`);
    assert.equal(
      original.operation.actionIntentId,
      request.command === 'CREATE'
        ? 'ACT-NOTIFICATIONS_CREATE_RESOURCE-V1'
        : 'ACT-NOTIFICATION_UPDATE_ACKNOWLEDGE-V1',
    );
    assert.equal(original.operation.state, 'SUCCEEDED');
    assert.equal(original.operation.truthState, 'SUCCESS');
    assert.equal(original.operation.revision, request.command === 'CREATE' ? '1' : '2');
    if (request.command === 'ACKNOWLEDGE')
      assert.equal(original.operation.resourceRef, request.notificationRef);
    const binding = notificationView.parse(await current(page, { view: 'LIST' }));
    const observed = notificationView.parse(
      await current(page, {
        view: 'OPERATION',
        actorKey: binding.actorKey,
        operationId: original.operation.operationId,
      }),
    );
    assert.deepEqual(observed.actor, original.actor);
    assert.equal(observed.actorKey, binding.actorKey);
    assert.deepEqual(observed.operation, original.operation);
    return binding;
  }

  async function settleRetainedBrowserRequest(page) {
    const pending = await page.evaluate(() =>
      JSON.parse(sessionStorage.getItem('openpc:notification-request:v1') ?? 'null'),
    );
    if (!pending) return;
    const live = await current(page, { view: 'LIST' });
    if (pending.request?.actorKey !== live.actorKey) {
      // The real UI clears obsolete hints when its authenticated binding changes.
      await expect(
        page.getByRole('button', { name: 'Create notification', exact: true }),
      ).toBeEnabled();
      assert.equal(
        await page.evaluate(() => sessionStorage.getItem('openpc:notification-request:v1')),
        null,
      );
      return;
    }
    const read = async (name) =>
      readFile(join(artifacts, name), 'utf8')
        .then(JSON.parse)
        .catch((error) => {
          if (error.code === 'ENOENT') return undefined;
          throw error;
        });
    const originalCreate = await read('original-create.json');
    const originalAck = await read('original-acknowledgement.json');
    const population = await read('populated-metadata.json');
    const known = [originalCreate, originalAck, ...(population?.cases ?? [])].find(
      (entry) => entry?.request?.requestKey === pending.request?.requestKey,
    );
    if (known?.result?.operation) {
      assert.deepEqual(pending.request, known.request);
      await readKnownOperation(page, known);
      // A missing hint never authorizes a POST. Real reauthentication may clear
      // obsolete browser hints; this driver does not fabricate or rewrite them.
      assert.equal(
        pending.operationId,
        known.result.operation.operationId,
        'KNOWN_OPERATION_READ_ONLY_REAUTHENTICATION_REQUIRED',
      );
      const recovered = response(page, 'GET', 'OPERATION');
      await page.getByRole('button', { name: 'Recover original result', exact: true }).click();
      assert.equal((await recovered).status(), 200);
      const effect = response(page, 'GET', 'DETAIL');
      await page.getByRole('button', { name: 'Read operation notification', exact: true }).click();
      assert.equal((await effect).status(), 200);
      await expect(
        page.getByRole('region', { name: 'Original request recovery', exact: true }),
      ).toHaveCount(0);
      return;
    }
    const stale = await read('original-stale-request.json');
    assert.ok(
      stale && pending.uncertain === false && !pending.operationId,
      'NOTIFICATION_UNKNOWN_BROWSER_OUTCOME_BLOCKED',
    );
    assert.deepEqual(pending.request, stale);
    const refreshed = response(page, 'GET', 'LIST');
    await page
      .getByRole('button', { name: 'Dismiss rejected request and refresh', exact: true })
      .click();
    assert.equal((await refreshed).status(), 200);
  }

  async function runPopulatedMetadata(maker, checker, originalCreate, originalAck, originalRef) {
    // Twenty-six distinct review notices are the minimum for this filtered
    // 25-row collection. They describe local review purposes, not delivery events.
    const purposes = [
      'participant.binding',
      'privacy.binding',
      'session.binding',
      'read.authority',
      'create.authority',
      'message.identity',
      'resource.reference',
      'severity.info',
      'severity.warning',
      'severity.error',
      'severity.critical',
      'unread.state',
      'acknowledged.state',
      'inspect.readonly',
      'operation.identity',
      'receipt.binding',
      'outbox.binding',
      'count.completeness',
      'cursor.continuation',
      'cursor.integrity',
      'cursor.session',
      'filter.state',
      'filter.severity',
      'sort.ascending',
      'sort.descending',
      'restart.readback',
    ];
    const file = join(artifacts, 'populated-metadata.json');
    let retained = await readFile(file, 'utf8')
      .then(JSON.parse)
      .catch((error) => {
        if (error.code === 'ENOENT') return undefined;
        throw error;
      });
    const persist = async () => {
      const temporary = `${file}.tmp`;
      await writeFile(temporary, JSON.stringify(retained), { mode: 0o600 });
      await rename(temporary, file);
    };
    const rows = async (field, value, sort = 'updatedAt') => {
      const columns = {
        resourceRef: 'resource_ref',
        state: 'state',
        severity: 'severity',
        messageKey: 'message_key',
      };
      assert.ok(Object.hasOwn(columns, field));
      assert.ok(['updatedAt', '-updatedAt'].includes(sort));
      const direction = sort === 'updatedAt' ? 'asc' : 'desc';
      return (
        await pool.query(
          `select notification_id::text id, state, revision::text, severity, message_key as "messageKey", resource_ref as "resourceRef"
       from control.notification where participant_id=$1 and privacy_domain_id=$2 and ${columns[field]}=$3
       order by updated_at ${direction},notification_id ${direction}`,
          [participantId, privacyDomainId, value],
        )
      ).rows;
    };
    const snapshot = async (ids) => {
      const values = [participantId, privacyDomainId, ids];
      const items = (
        await pool.query(
          `select notification_id,state,revision::text,severity,resource_ref,message_key,created_at::text,updated_at::text from control.notification where participant_id=$1 and privacy_domain_id=$2 and notification_id=any($3::uuid[]) order by notification_id`,
          values,
        )
      ).rows;
      const receipts = (
        await pool.query(
          `select a.*,k.public_key_spki_der from control.audit_occurrence a join control.business_signing_key k using(participant_id,privacy_domain_id,signer_id) where a.participant_id=$1 and a.privacy_domain_id=$2 and a.aggregate_type='notification' and a.aggregate_id=any($3::uuid[]) order by a.aggregate_id,a.after_revision`,
          values,
        )
      ).rows;
      const outbox = (
        await pool.query(
          `select event_id,receipt_id,correlation_id,proof_kind,sequence_namespace,business_sequence,payload_cbor from control.outbox_event where participant_id=$1 and privacy_domain_id=$2 and aggregate_type='notification' and aggregate_id=any($3::uuid[]) order by receipt_id`,
          values,
        )
      ).rows;
      return { items, receipts, outbox };
    };
    const originalIds = [originalRef.slice(-36)];
    const originalSealed = await snapshot(originalIds);
    assert.equal(originalSealed.items.length, 1);
    assert.equal(originalSealed.items[0].state, 'ACKNOWLEDGED');
    assert.equal(originalSealed.items[0].revision, '2');
    assert.equal(originalSealed.receipts.length, 2);
    assert.equal(originalSealed.outbox.length, 2);
    assert.deepEqual(
      originalSealed.receipts.map((row) => row.operation_id),
      [originalCreate.result.operation.operationId, originalAck.result.operation.operationId],
    );
    if (!retained) {
      assert.deepEqual(
        await rows('resourceRef', originalRef),
        [],
        'Unrecorded population requires reconciliation, never replacement intents',
      );
      const suffix = randomBytes(6).toString('hex');
      retained = {
        originalRef,
        cases: purposes.map((purpose, index) => ({
          purpose,
          intent: {
            severity: ['INFO', 'WARNING', 'ERROR', 'CRITICAL'][index % 4],
            messageKey: `notification.metadata.review.${purpose}.${suffix}`,
            resourceRef: originalRef,
            reason: `Request local metadata review of ${purpose} for the completed notification.`,
          },
        })),
      };
      await persist();
    }
    assert.equal(retained.originalRef, originalRef);
    assert.equal(retained.cases.length, 26);
    assert.ok(!retained.firstFailure, 'POPULATED_FIRST_FAILURE_REQUIRES_CLASSIFIED_RESUME');
    let phase = 'RETAINED_PREFLIGHT';
    try {
      const knownIds = [];
      let undispatched = false;
      for (const [index, entry] of retained.cases.entries()) {
        assert.equal(entry.purpose, purposes[index]);
        assert.equal(entry.intent.resourceRef, originalRef);
        assert.equal(entry.intent.severity, ['INFO', 'WARNING', 'ERROR', 'CRITICAL'][index % 4]);
        assert.equal(
          entry.intent.reason,
          `Request local metadata review of ${entry.purpose} for the completed notification.`,
        );
        assert.match(
          entry.intent.messageKey,
          new RegExp(
            `^notification\\.metadata\\.review\\.${entry.purpose.replaceAll('.', '\\.')}\\.[a-f0-9]{12}$`,
            'u',
          ),
        );
        if (!entry.request) {
          assert.equal(entry.result, undefined);
          assert.equal(entry.status, undefined);
          undispatched = true;
          continue;
        }
        assert.ok(!undispatched, 'POPULATED_CAPTURE_ORDER_BLOCKED');
        assert.equal(entry.status, 202, 'POPULATED_UNKNOWN_OR_DENIED_OUTCOME_BLOCKED');
        const request = notificationCommand.parse(entry.request);
        assert.equal(request.command, 'CREATE');
        for (const [key, value] of Object.entries(entry.intent)) assert.equal(request[key], value);
        await readKnownOperation(maker, entry);
        knownIds.push(entry.result.operation.resourceRef.slice(-36));
      }
      assert.equal(new Set(retained.cases.map((entry) => entry.intent.messageKey)).size, 26);
      assert.deepEqual(
        (await rows('resourceRef', originalRef)).map((row) => row.id).sort(),
        [...knownIds].sort(),
        'Retained effects must match exactly before dispatch',
      );
      await maker.reload();
      await expect(
        maker.getByRole('button', { name: 'Create notification', exact: true }),
      ).toBeEnabled();
      for (const [index, entry] of retained.cases.entries()) {
        if (entry.request) continue; // Known original operations were read above, never replayed.
        phase = `CREATE_${index + 1}`;
        await maker
          .getByRole('combobox', { name: /^Severity/u })
          .selectOption(entry.intent.severity);
        for (const [label, value] of [
          ['Message key', entry.intent.messageKey],
          ['Resource reference (optional)', entry.intent.resourceRef],
          ['Reason', entry.intent.reason],
        ])
          await maker.getByLabel(label, { exact: true }).fill(value);
        let failure,
          finished = false,
          dispatched = false;
        const capture = async (route) => {
          if (route.request().method() !== 'POST') return route.continue();
          try {
            assert.ok(!dispatched, 'Duplicate populated submission');
            dispatched = true;
            entry.request = notificationCommand.parse(route.request().postDataJSON());
            assert.equal(entry.request.command, 'CREATE');
            for (const [key, value] of Object.entries(entry.intent))
              assert.equal(entry.request[key], value);
            await persist(); // Durably preserve the exact original before forwarding.
            const actual = await route.fetch();
            const body = await actual.json();
            entry.status = actual.status();
            entry.result =
              actual.status() === 202 ? notificationView.parse(body) : { code: body.code };
            await persist();
            assert.equal(entry.status, 202, 'Populated CREATE rejected; no replacement key');
            await route.fulfill({ response: actual });
            finished = true;
          } catch (error) {
            failure = error;
            await route.abort('failed').catch(() => {});
          }
        };
        await maker.route(`**${endpoint}`, capture);
        try {
          await maker.getByRole('button', { name: 'Create notification', exact: true }).click();
          await expect.poll(() => finished || !!failure, { timeout: 30000 }).toBe(true);
          if (failure) throw failure;
          await readKnownOperation(maker, entry);
          const readback = response(maker, 'GET', 'DETAIL');
          await maker
            .getByRole('button', { name: 'Read operation notification', exact: true })
            .click();
          const actual = await readback;
          assert.equal(actual.status(), 200);
          const detail = notificationView.parse(await actual.json());
          assert.equal(detail.kind, 'DETAIL');
          assert.equal(detail.notification.notificationId, entry.result.operation.resourceRef);
          assert.equal(detail.notification.state, 'UNREAD');
          assert.equal(detail.notification.revision, '1');
          for (const key of ['severity', 'messageKey', 'resourceRef'])
            assert.equal(detail.notification[key], entry.intent[key]);
          await expect(
            maker.getByRole('region', { name: 'Original request recovery', exact: true }),
          ).toHaveCount(0);
          await expect(
            maker.getByRole('button', { name: 'Create notification', exact: true }),
          ).toBeEnabled();
        } finally {
          await maker.unroute(`**${endpoint}`, capture);
        }
      }
      phase = 'SIGNED_EFFECTS';
      const ids = retained.cases.map((entry) => entry.result.operation.resourceRef.slice(-36));
      assert.equal(new Set(ids).size, 26);
      assert.equal(new Set(retained.cases.map((entry) => entry.request.requestKey)).size, 26);
      const sealed = await snapshot(ids);
      assert.equal(sealed.items.length, 26);
      assert.equal(sealed.receipts.length, 26);
      assert.equal(sealed.outbox.length, 26);
      const hash = (bytes) => createHash('sha256').update(bytes).digest();
      for (const entry of retained.cases) {
        const id = entry.result.operation.resourceRef.slice(-36);
        const item = sealed.items.find((row) => row.notification_id === id);
        assert.equal(item.state, 'UNREAD');
        assert.equal(item.revision, '1');
        assert.equal(item.message_key, entry.intent.messageKey);
        assert.equal(item.resource_ref, entry.intent.resourceRef);
        assert.equal(item.severity, entry.intent.severity);
        const receipts = sealed.receipts.filter((row) => row.aggregate_id === id);
        assert.equal(receipts.length, 1);
        const row = receipts[0];
        assert.ok(
          kernel.verifyReceiptCose(row.public_key_spki_der, row.receipt_cbor, row.cose_sign1),
        );
        const receipt = kernel.decodeAdmittedReceipt(row.receipt_cbor);
        assert.equal(receipt.participantId, participantId);
        assert.equal(receipt.privacyDomainId, privacyDomainId);
        assert.equal(receipt.aggregateType, 'notification');
        assert.equal(receipt.aggregateId, id);
        assert.equal(receipt.before.revision, 0n);
        assert.equal(receipt.after.revision, 1n);
        assert.equal(receipt.operationId, entry.result.operation.operationId);
        assert.equal(row.operation_id, receipt.operationId);
        assert.equal(receipt.actionIntentId, 'ACT-NOTIFICATIONS_CREATE_RESOURCE-V1');
        assert.equal(row.action_intent_id, receipt.actionIntentId);
        assert.deepEqual(hash(row.before_state_preimage), receipt.before.stateDigest);
        assert.deepEqual(hash(row.after_state_preimage), receipt.after.stateDigest);
        assert.deepEqual(hash(row.receipt_cbor), row.receipt_digest);
        const events = sealed.outbox.filter((event) => event.receipt_id === row.receipt_id);
        assert.equal(events.length, 1);
        assert.equal(receipt.outboxEvents.length, 1);
        assert.equal(events[0].event_id, receipt.outboxEvents[0].eventId);
        assert.equal(events[0].correlation_id, receipt.operationId);
        assert.equal(events[0].proof_kind, 'BUSINESS_RECEIPT_REFERENCE');
        assert.equal(events[0].sequence_namespace, 'CONTROL_BUSINESS_TRANSITION_V1');
        assert.equal(
          BigInt(events[0].business_sequence),
          receipt.outboxEvents[0].aggregateSequence,
        );
        assert.deepEqual(hash(events[0].payload_cbor), receipt.outboxEvents[0].payloadDigest);
      }
      const unchanged = async () => {
        assert.ok(
          isDeepStrictEqual(await snapshot(ids), sealed),
          'Collection reads and denials cannot acknowledge or change signed effects',
        );
        assert.ok(
          isDeepStrictEqual(await snapshot(originalIds), originalSealed),
          'Original CREATE/ACK signed bytes must remain unchanged',
        );
      };
      const viewRoot = join(artifacts, `populated-${Date.now()}-${randomBytes(6).toString('hex')}`);
      await mkdir(viewRoot, { recursive: true, mode: 0o700 });
      const walk = async (field, value, sort, capturePages = false) => {
        const expected = await rows(field, value, sort);
        await maker.getByRole('combobox', { name: /^Filter field/u }).selectOption(field);
        await maker.getByLabel('Filter value', { exact: true }).fill(value);
        await maker.getByRole('combobox', { name: /^Sort/u }).selectOption(sort);
        const refreshed = response(maker, 'GET', 'LIST');
        await maker.getByRole('button', { name: 'Refresh notifications', exact: true }).click();
        let reply = await refreshed;
        const seen = [],
          cursors = new Set();
        let snapshotRevision, first;
        for (let pageIndex = 0; ; pageIndex++) {
          assert.ok(pageIndex <= Math.ceil(expected.length / 25), 'Pagination must terminate');
          assert.equal(reply.status(), 200);
          assert.equal(reply.headers()['cache-control'], 'no-store');
          const view = notificationView.parse(await reply.json());
          assert.equal(view.kind, 'LIST');
          assert.deepEqual(view.actor, { participantId, privacyDomainId });
          first ??= view;
          assert.equal(view.actorKey, first.actorKey);
          snapshotRevision ??= view.page.snapshotRevision;
          assert.equal(view.page.snapshotRevision, snapshotRevision);
          assert.equal(view.page.total, String(expected.length));
          assert.equal(view.page.completeness, 'COMPLETE');
          assert.equal(view.page.authorizedEmpty, expected.length === 0);
          await expect(
            maker.getByText(`${expected.length} matching notifications`, { exact: false }),
          ).toContainText('Completeness: COMPLETE');
          const slice = expected.slice(seen.length, seen.length + 25);
          assert.deepEqual(
            view.page.items.map((item) => item.notificationId.slice(-36)),
            slice.map((item) => item.id),
          );
          const visible = maker.getByRole('list', { name: 'Notification results', exact: true });
          if (slice.length) {
            await expect(visible.getByRole('listitem')).toHaveCount(slice.length);
            await expect(visible.getByRole('button')).toHaveText(
              slice.map((item) => `Inspect ${item.messageKey}`),
            );
            for (const [index, item] of slice.entries())
              await expect(visible.getByRole('listitem').nth(index)).toContainText(
                `${item.severity} · ${item.state} · ${item.messageKey}`,
              );
            const selected = await inspect(maker, slice[0].messageKey);
            assert.equal(selected.notification.notificationId, view.page.items[0].notificationId);
            assert.equal(selected.notification.state, slice[0].state);
            assert.equal(selected.notification.revision, slice[0].revision);
            assert.equal(selected.actorKey, view.actorKey);
          } else {
            await expect(visible).toHaveCount(0);
            await expect(
              maker.getByText('No authorized notifications match this filter.', { exact: true }),
            ).toHaveCount(2);
          }
          for (const item of view.page.items) {
            assert.equal(item.participantId, `urn:openpc:participant:${participantId}`);
            seen.push(item.notificationId.slice(-36));
          }
          const next = maker.getByRole('button', { name: 'Next page', exact: true });
          if (capturePages) {
            for (const width of [1440, 360]) {
              await maker.setViewportSize({ width, height: 1000 });
              assert.ok(
                await maker.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
              );
              await maker.screenshot({
                path: join(viewRoot, `page-${pageIndex + 1}-${width}.png`),
                fullPage: true,
              });
            }
          }
          if (!view.page.nextCursor) {
            await expect(next).toBeDisabled();
            break;
          }
          assert.ok(!cursors.has(view.page.nextCursor));
          cursors.add(view.page.nextCursor);
          await expect(next).toBeEnabled();
          await next.focus();
          const advanced = response(maker, 'GET', 'LIST');
          await maker.keyboard.press('Enter');
          reply = await advanced;
          const query = new URL(reply.url()).searchParams;
          assert.equal(query.get('cursor'), view.page.nextCursor);
          assert.equal(query.get('filter'), `${field}:eq:${value}`);
          assert.equal(query.get('sort'), sort);
          assert.equal(query.get('limit'), '25');
        }
        assert.deepEqual(
          seen,
          expected.map((item) => item.id),
        );
        assert.equal(new Set(seen).size, expected.length);
        await unchanged();
        return first;
      };
      phase = 'PAGINATION_FILTERS';
      const first = await walk('resourceRef', originalRef, 'updatedAt', true);
      assert.equal(first.page.total, '26');
      assert.equal(first.page.items.length, 25);
      assert.ok(first.page.nextCursor);
      await walk('resourceRef', originalRef, '-updatedAt');
      for (const state of ['UNREAD', 'ACKNOWLEDGED', 'READ'])
        await walk('state', state, 'updatedAt');
      for (const severity of ['INFO', 'WARNING', 'ERROR', 'CRITICAL'])
        await walk('severity', severity, '-updatedAt');
      await walk('messageKey', `${retained.cases[0].intent.messageKey}.absent`, 'updatedAt');
      phase = 'CURSOR_DENIALS';
      const parameters = {
        view: 'LIST',
        limit: '25',
        filter: `resourceRef:eq:${originalRef}`,
        sort: 'updatedAt',
        cursor: first.page.nextCursor,
      };
      // Use the genuine owner cursor. No payload construction, signing, or fake
      // foreign scope: checker supplies the other existing authenticated session.
      const tampered = `${first.page.nextCursor.slice(0, -1)}${first.page.nextCursor.endsWith('A') ? 'B' : 'A'}`;
      for (const [page, query] of [
        [maker, { ...parameters, cursor: tampered }],
        [maker, { ...parameters, sort: '-updatedAt' }],
        [maker, { ...parameters, filter: 'state:eq:UNREAD' }],
        [checker, parameters],
      ]) {
        const denied = await page.request.get(`${origin}${endpoint}?${new URLSearchParams(query)}`);
        assert.equal(denied.status(), 400);
        assert.equal((await denied.json()).code, 'PC-DATA-6004');
        await unchanged();
      }
      const otherBinding = await current(checker, { view: 'LIST' });
      const wrongScope = await maker.request.get(
        `${origin}${endpoint}?${new URLSearchParams({ view: 'DETAIL', actorKey: otherBinding.actorKey, notificationRef: retained.cases[0].result.operation.resourceRef })}`,
      );
      assert.equal(wrongScope.status(), 404);
      assert.equal((await wrongScope.json()).code, 'PC-AUTH-0005');
      await unchanged();
      phase = 'RESTART';
      await restartBrowserServices();
      await expect
        .poll(
          async () => {
            try {
              return (await maker.request.get(`${origin}${endpoint}?view=LIST`)).status();
            } catch {
              return 0;
            }
          },
          { timeout: 30000, intervals: [250, 500, 1000] },
        )
        .toBe(200);
      await unchanged();
      await readKnownOperation(maker, originalCreate);
      await readKnownOperation(maker, originalAck);
      for (const entry of retained.cases) await readKnownOperation(maker, entry);
      await maker.reload();
      await walk('resourceRef', originalRef, 'updatedAt');
      assert.ok(
        isDeepStrictEqual(JSON.parse(await readFile(file, 'utf8')), retained),
        'Restart must preserve captured requests/results',
      );
      process.stdout.write(
        `OPENPC_NOTIFICATION_POPULATED|PASS|new-metadata=26|original-effects=2|signed-creates=26|next-page|filters|stable-sort|inspect-no-ack|cursor-denials|restart|visual-inspection=PENDING|delivery=OPEN|artifacts=${viewRoot}\n`,
      );
    } catch (error) {
      retained.firstFailure ??= {
        phase,
        state: /BLOCKED|REAUTHENTICATION_REQUIRED/u.test(error.message) ? 'BLOCKED' : 'FAIL',
      };
      await persist();
      throw error;
    }
  }
  // Optional connected endpoint segment in the EXISTING driver. Canonical runtime
  // composition must supply an endpoint created through its supported owner plus
  // the actual LS-NOTIFICATION peer/provider/gateway. This segment does not claim
  // whole N3 acceptance. CREATE/UPDATE and process-private UNKNOWN are explicit opt-ins. No SQL
  // business state or private authority is seeded to get past those prerequisites.
  // Optional CREATE segment uses the same real browser/WebAuthn fixture. The input
  // is an installation-owned destination reference, never a seeded successful row.
  // Scope-wide snapshots catch an unexpected new aggregate as well as changes
  // to the selected endpoint. Signed bytes and outbox cardinality stay exact.
  const endpointEffects = async () => ({
    endpoints: (await pool.query(endpointEffectQueries.endpoints, [participantId, privacyDomainId]))
      .rows,
    operations: (
      await pool.query(endpointEffectQueries.operations, [
        participantId,
        privacyDomainId,
        [
          'ACT-NOTIFICATION_ENDPOINTS_CREATE_RESOURCE-V1',
          'ACT-NOTIFICATION_ENDPOINTS_UPDATE_RESOURCE-V1',
          'ACT-NOTIFICATION_UPDATE_VERIFY-V1',
        ],
      ])
    ).rows,
    attempts: (await pool.query(endpointEffectQueries.attempts, [participantId, privacyDomainId]))
      .rows,
    receipts: (await pool.query(endpointEffectQueries.receipts, [participantId, privacyDomainId]))
      .rows,
    events: (await pool.query(endpointEffectQueries.events, [participantId, privacyDomainId])).rows,
  });
  let endpointSqlChecked = false;
  async function preflightEndpointSql() {
    if (endpointSqlChecked) return;
    for (const [name, sql] of Object.entries(endpointEffectQueries)) {
      await pool.query(
        `EXPLAIN ${sql}`,
        name === 'operations'
          ? [
              participantId,
              privacyDomainId,
              [
                'ACT-NOTIFICATION_ENDPOINTS_CREATE_RESOURCE-V1',
                'ACT-NOTIFICATION_ENDPOINTS_UPDATE_RESOURCE-V1',
                'ACT-NOTIFICATION_UPDATE_VERIFY-V1',
              ],
            ]
          : [participantId, privacyDomainId],
      );
    }
    endpointSqlChecked = true;
  }
  async function endpointDenials(maker, checker, review) {
    const original = review.request;
    // A different reason makes this a distinct reviewed candidate, not an
    // idempotency-key variation intended to escape an earlier business denial.
    const fields = endpointCommand.options[original.command === 'CREATE' ? 3 : 4].parse(
      Object.fromEntries(
        Object.entries({ ...original, command: `REVIEW_${original.command}` }).filter(
          ([key]) => key !== 'candidateDigest',
        ),
      ),
    );
    const cases = [
      { name: 'missing-candidate-step-up', page: maker, status: 404, code: 'PC-AUTH-0005' },
      { name: 'different-actor', page: checker, status: 404, code: 'PC-AUTH-0005' },
      { name: 'candidate-binding', page: maker, status: 412, code: 'PC-DATA-6007' },
    ];
    if (original.command === 'UPDATE')
      cases.push({
        name: 'unavailable-replacement',
        page: maker,
        status: 412,
        code: 'PC-DATA-6007',
      });
    for (const entry of cases) {
      const before = await endpointEffects();
      const reviewInput = {
        ...fields,
        requestKey: randomUUID(),
        reason: `Independent ${original.command} denial case: ${entry.name}.`,
      };
      let request;
      if (entry.name === 'unavailable-replacement') {
        request = { ...reviewInput, replacementDigest: `sha256:${'0'.repeat(64)}` };
      } else {
        const response = await maker.request.post(`${origin}${notificationEndpointWorkbench}`, {
          headers: { Origin: origin },
          data: reviewInput,
        });
        assert.equal(response.status(), 200);
        const fresh = endpointView.parse(await response.json());
        assert.equal(fresh.kind, `${original.command}_REVIEW`);
        request =
          entry.name === 'candidate-binding'
            ? { ...fresh.request, candidateDigest: `sha256:${'0'.repeat(64)}` }
            : fresh.request;
      }
      const file = `endpoint-denial-${original.command}-${entry.name}-${request.requestKey}.json`;
      await save(file, { request });
      const denied = await entry.page.request.post(`${origin}${notificationEndpointWorkbench}`, {
        headers: { Origin: origin },
        data: request,
      });
      const problem = await denied.json();
      await save(file, { request, status: denied.status(), problem });
      assertEndpointDenial({
        status: denied.status(),
        problem,
        before,
        after: await endpointEffects(),
        expectedStatus: entry.status,
        code: entry.code,
      });
    }
    process.stdout.write(
      `OPENPC_NOTIFICATION_ENDPOINT_DENIALS|PASS|command=${original.command}|candidate-step-up|actor-binding|candidate-binding|credential-rotation=OPEN\n`,
    );
  }
  async function inspectEndpointError(page, name) {
    const alert = page
      .getByRole('region', { name: 'Notification endpoints', exact: true })
      .getByRole('alert');
    await expect(alert).toBeFocused();
    for (const width of [1440, 360]) {
      await page.setViewportSize({ width, height: 1000 });
      assert.deepEqual(
        (await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze())
          .violations,
        [],
      );
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
      await page.screenshot({
        path: join(artifacts, `notification-endpoint-${name}-${width}.png`),
        fullPage: true,
      });
    }
  }
  async function recoverEndpointAcrossLogout(page, original) {
    const before = await endpointEffects();
    const originalSession = await page.evaluate(async () => {
      const response = await fetch('/api/v1/ui/local-session', { cache: 'no-store' });
      if (!response.ok) throw new Error('Original endpoint account is unavailable');
      return response.json();
    });
    assert.equal(originalSession.authenticated, true);
    assert.ok(originalSession.principalId);
    const seen = Promise.withResolvers();
    const deadline = setTimeout(
      () => seen.reject(new Error('Original replay did not reach its owner within 30 seconds')),
      30_000,
    );
    const release = Promise.withResolvers();
    const finished = Promise.withResolvers();
    // Attach a rejection observer before the route can fail.
    void seen.promise.catch(() => {});
    const hold = async (route) => {
      try {
        const response = await route.fetch();
        assertEndpointReplay({
          request: route.request().postDataJSON(),
          status: response.status(),
          result: await response.json(),
          original,
          before,
          after: await endpointEffects(),
        });
        seen.resolve();
        await release.promise;
        // The real document has already reloaded following session revocation.
        await route.fulfill({ response });
        finished.resolve();
      } catch (error) {
        seen.reject(error);
        finished.reject(error);
        await route.abort('failed').catch(() => {});
      }
    };
    void finished.promise.catch(() => {});
    await page.route(`**${notificationEndpointWorkbench}`, hold, { times: 1 });
    try {
      await page
        .getByRole('button', {
          name:
            original.request.command === 'CREATE'
              ? 'Recover original creation'
              : 'Recover original replacement',
          exact: true,
        })
        .click();
      await seen.promise;
      const revoked = page.waitForResponse(
        (value) =>
          new URL(value.url()).pathname === '/api/v1/ui/local-session' &&
          value.request().method() === 'DELETE',
      );
      await Promise.all([
        page.waitForEvent('load'),
        page.getByRole('button', { name: 'Revoke local session', exact: true }).click(),
      ]);
      assert.equal((await revoked).status(), 202, 'Genuine Identity revocation must finish');
      release.resolve();
      await finished.promise;
      const anonymous = await page.request.get(
        `${origin}${notificationEndpointWorkbench}?view=LIST`,
      );
      assert.equal(anonymous.status(), 404);
      await expect(
        page.getByRole('region', { name: 'Endpoint operation', exact: true }),
      ).toHaveCount(0);
      await expect(page.getByRole('region', { name: 'Endpoint details', exact: true })).toHaveCount(
        0,
      );
      await expect(
        page.getByRole('region', { name: 'Original endpoint request recovery', exact: true }),
      ).toHaveCount(0);
      await authenticate(page, 'viewer', privacyDomainId, {
        participantWorkbench: false,
        expectedPrincipalId: originalSession.principalId,
      });
      await page.goto(`${origin}/home/session?view=notification-endpoints`);
      await expect(
        page.getByRole('button', { name: 'Refresh endpoints', exact: true }),
      ).toBeEnabled();
      const listed = await page.request.get(`${origin}${notificationEndpointWorkbench}?view=LIST`);
      assert.equal(listed.status(), 200);
      const current = endpointView.parse(await listed.json());
      assert.notEqual(
        current.actorKey,
        original.request.actorKey,
        'Fresh Identity session must change actor binding',
      );
      // The old request is now inadmissible even though the same human signed in.
      const old = await page.request.post(`${origin}${notificationEndpointWorkbench}`, {
        headers: { Origin: origin },
        data: original.request,
      });
      assertEndpointDenial({
        status: old.status(),
        problem: await old.json(),
        before,
        after: await endpointEffects(),
        expectedStatus: 404,
        code: 'PC-AUTH-0005',
      });
      const known = page.waitForResponse(
        (value) =>
          value.request().method() === 'GET' &&
          new URL(value.url()).pathname === notificationEndpointWorkbench &&
          new URL(value.url()).searchParams.get('view') === 'OPERATION',
      );
      await page
        .getByLabel('Existing endpoint operation ID', { exact: true })
        .fill(original.result.operation.operationId);
      await page.getByRole('button', { name: 'Read endpoint operation', exact: true }).click();
      const readback = await known;
      assert.equal(readback.status(), 200);
      assert.deepEqual((await readback.json()).operation, original.result.operation);
      await expect(
        page.getByRole('region', { name: 'Endpoint operation', exact: true }),
      ).toContainText(original.result.operation.operationId);
      assert.deepEqual(await endpointEffects(), before);
      process.stdout.write(
        `OPENPC_NOTIFICATION_ENDPOINT_REPLAY_LOGOUT|PASS|command=${original.request.command}|exact-duplicate|real-logout|late-response-discard|real-oidc|old-actor-denied|known-operation-read\n`,
      );
    } finally {
      clearTimeout(deadline);
      release.resolve();
      await page.unroute(`**${notificationEndpointWorkbench}`, hold);
    }
  }
  async function prepareEndpointContext(page) {
    // Replay/logout remains a separate selectable predicate; it cannot establish
    // first-mutation invalidation. Neither mode creates a second business intent.
    if (endpointInflightMode === 'replay-logout') return undefined;
    const response = await page.request.get(`${origin}/api/v1/ui/local-session`);
    assert.equal(response.status(), 200);
    const session = await response.json();
    const alternate = requireEndpointMutationContext(
      session,
      participantId,
      privacyDomainId,
      endpointInflightMode,
    );
    await page
      .getByRole('combobox', { name: 'Organization workspace', exact: true })
      .selectOption(alternate.privacyDomainId);
    const committed = Promise.withResolvers(),
      release = Promise.withResolvers(),
      done = Promise.withResolvers();
    void committed.promise.catch(() => {});
    void done.promise.catch(() => {});
    return { session, alternate, before: await endpointEffects(), committed, release, done };
  }
  async function finishEndpointFirstContext(page, gate) {
    let record,
      failure,
      mutationAborted = false,
      transitioned = false;
    const ownerRelease = Promise.withResolvers(),
      ownerDone = Promise.withResolvers();
    const ownerPath = '/api/v1/ui/session/context';
    const root = await page
      .getByRole('region', { name: 'Notification endpoints', exact: true })
      .elementHandle();
    assert.ok(root, 'Mounted endpoint component required');
    const failed = (request) => {
      if (
        new URL(request.url()).pathname === notificationEndpointWorkbench &&
        request.method() === 'POST' &&
        /aborted|cancelled|canceled/iu.test(request.failure()?.errorText ?? '')
      )
        mutationAborted = true;
    };
    page.on('requestfailed', failed);
    const clear = async () => {
      assert.ok(
        await root.evaluate((element) => element.isConnected),
        'Context test must retain the original mounted endpoint component',
      );
      for (const name of [
        'Endpoint details',
        'Endpoint operation',
        'Original endpoint request recovery',
        'Endpoint creation review',
        'Endpoint replacement review',
      ])
        await expect(page.getByRole('region', { name, exact: true })).toHaveCount(0);
      await expect(page.getByRole('list', { name: 'Endpoint results', exact: true })).toHaveCount(
        0,
      );
      for (const name of [
        'Endpoint destination reference',
        'Creation reason',
        'Existing endpoint operation ID',
        'Filter value',
      ])
        await expect(page.getByLabel(name, { exact: true })).toHaveValue('');
      assert.equal(
        await page.evaluate(() =>
          sessionStorage.getItem('openpc:notification-endpoint-request:v1'),
        ),
        null,
      );
    };
    const holdOwner = async (route) => {
      if (route.request().method() !== 'POST') return route.continue();
      try {
        const response = await route.fetch({ timeout: 15000 });
        assert.equal(response.status(), 201);
        const current = await response.json();
        assert.equal(current.participantId, participantId);
        assert.equal(current.privacyDomainId, gate.alternate.privacyDomainId);
        assert.notEqual(current.sessionId, gate.session.sessionId);
        transitioned = true;
        await ownerRelease.promise;
        await route.fulfill({ response });
      } catch (error) {
        failure ??= error;
        await route.abort('failed').catch(() => {});
      } finally {
        ownerDone.resolve();
      }
    };
    await page.route(`**${ownerPath}`, holdOwner);
    try {
      // A finite gate waits for the actual first public mutation, not a replay.
      await expect
        .poll(() => gate.record !== undefined || gate.failure !== undefined, { timeout: 30000 })
        .toBe(true);
      if (gate.failure) throw gate.failure;
      record = await gate.committed.promise;
      const sealed = await endpointEffects();
      assertEndpointFirstCommit(gate.before, sealed, record);
      const natural = await page.evaluate(() =>
        JSON.parse(sessionStorage.getItem('openpc:notification-endpoint-request:v1') ?? 'null'),
      );
      assert.deepEqual(natural?.request, record.request);
      assert.equal(natural.uncertain, true);
      assert.equal(natural.operationId, undefined);
      // Keep the exact duplicate/no-effect predicate before actor invalidation.
      const duplicate = await page.request.post(`${origin}${notificationEndpointWorkbench}`, {
        headers: { Origin: origin },
        data: record.request,
      });
      assertEndpointReplay({
        request: record.request,
        status: duplicate.status(),
        result: await duplicate.json(),
        original: record,
        before: sealed,
        after: await endpointEffects(),
      });
      await page
        .getByRole('button', {
          name: 'Verify and enter workspace',
          exact: true,
        })
        .click();
      await expect.poll(() => transitioned || failure !== undefined, { timeout: 30000 }).toBe(true);
      if (failure) throw failure;
      // The real owner has committed; its response is held so reload cannot
      // erase the component and masquerade as live protected-state invalidation.
      await clear();
      gate.release.resolve();
      await gate.done.promise;
      if (gate.failure && !mutationAborted) throw gate.failure;
      await page.evaluate(
        () => new Promise((done) => requestAnimationFrame(() => requestAnimationFrame(done))),
      );
      await clear();
      await expect(
        page
          .getByRole('region', { name: 'Notification endpoints', exact: true })
          .getByRole('alert'),
      ).toHaveCount(0);
      assert.deepEqual(await endpointEffects(), sealed);
      await page.screenshot({
        path: join(artifacts, `endpoint-first-${record.request.command}-context-cleared.png`),
        fullPage: true,
      });
      const loaded = page.waitForEvent('load');
      void loaded.catch(() => {});
      ownerRelease.resolve();
      await ownerDone.promise;
      if (failure) throw failure;
      await loaded;
      const sessionReply = await page.request.get(`${origin}/api/v1/ui/local-session`);
      assert.equal(sessionReply.status(), 200);
      const changed = await sessionReply.json();
      assert.equal(changed.authenticated, true);
      assert.equal(changed.principalId, gate.session.principalId);
      assert.equal(changed.privacyDomainId, gate.alternate.privacyDomainId);
      const oldRead = await page.request.get(
        `${origin}${notificationEndpointWorkbench}?${new URLSearchParams({ view: 'OPERATION', actorKey: record.request.actorKey, operationId: record.result.operation.operationId })}`,
      );
      assertEndpointDenial({
        status: oldRead.status(),
        problem: await oldRead.json(),
        before: sealed,
        after: await endpointEffects(),
        expectedStatus: 404,
        code: 'PC-AUTH-0005',
      });
      await page.unroute(`**${ownerPath}`, holdOwner);
      await restoreEndpointBrowserContext({
        page,
        origin,
        participantId,
        privacyDomainId,
        originalSession: gate.session,
      });
      await page.goto(`${origin}/home/session?view=notification-endpoints`);
      await expect(
        page.getByRole('button', { name: 'Read endpoint operation', exact: true }),
      ).toBeEnabled();
      const originalRead = page.waitForResponse(
        (value) =>
          value.request().method() === 'GET' &&
          new URL(value.url()).pathname === notificationEndpointWorkbench &&
          new URL(value.url()).searchParams.get('view') === 'OPERATION',
      );
      await page
        .getByLabel('Existing endpoint operation ID', { exact: true })
        .fill(record.result.operation.operationId);
      await page.getByRole('button', { name: 'Read endpoint operation', exact: true }).click();
      const result = await originalRead;
      assert.equal(result.status(), 200);
      assert.deepEqual((await result.json()).operation, record.result.operation);
      assert.deepEqual(await endpointEffects(), sealed);
      await save(`endpoint-first-${record.request.command}-context-result.json`, {
        state: 'PASS',
        operationId: record.result.operation.operationId,
        firstMutation: true,
        mountedBeforeAndAfter: true,
        replayLogout: 'NOT_EXECUTED',
      });
      process.stdout.write(
        `OPENPC_NOTIFICATION_ENDPOINT_FIRST_CONTEXT|PASS|command=${record.request.command}|first-commit|real-context|still-mounted|exact-duplicate|late-result-discard|original-operation-get|replay-logout=NOT_EXECUTED\n`,
      );
    } catch (error) {
      if (record)
        await save(`endpoint-first-${record.request.command}-context-result.json`, {
          state: 'FAIL',
          operationId: record.result.operation.operationId,
          firstMutation: true,
          acceptance: 'OPEN',
        });
      throw error;
    } finally {
      gate.release.resolve();
      ownerRelease.resolve();
      await page.unroute(`**${ownerPath}`, holdOwner);
      if (transitioned) await ownerDone.promise;
      if (gate.record || gate.failure) await gate.done.promise;
      page.off('requestfailed', failed);
      await root.dispose();
    }
  }
  async function runEndpointCreationBrowser(maker, checker) {
    const destinationRef = process.env.OPENPC_NOTIFICATION_ENDPOINT_DESTINATION_REF;
    const prior = await readFile(join(artifacts, 'endpoint-original-create.json'), 'utf8')
      .then(JSON.parse)
      .catch((error) => {
        if (error.code === 'ENOENT') return undefined;
        throw error;
      });
    if (!destinationRef && !prior) return undefined;
    await preflightEndpointSql();
    await maker.goto(`${origin}/home/session?view=notification-endpoints`);
    await expect(
      maker.getByRole('heading', { name: 'Notification endpoints', exact: true }),
    ).toBeVisible();
    let original = prior;
    if (!original) {
      assert.equal(
        process.env.OPENPC_NOTIFICATION_ENDPOINT_REF,
        undefined,
        'Choose the supported browser CREATE segment or an existing endpoint, not both',
      );
      assert.equal(
        await maker.evaluate(() =>
          sessionStorage.getItem('openpc:notification-endpoint-request:v1'),
        ),
        null,
        'Unresolved original endpoint request must be recovered before CREATE',
      );
      const contextGate = await prepareEndpointContext(maker);
      await maker
        .getByLabel('Endpoint channel', { exact: true })
        .selectOption(process.env.OPENPC_NOTIFICATION_ENDPOINT_CHANNEL ?? 'WEBHOOK');
      await maker
        .getByLabel('Endpoint destination reference', { exact: true })
        .fill(destinationRef);
      await maker
        .getByLabel('Creation reason', { exact: true })
        .fill('Create the admitted endpoint through real browser WebAuthn.');
      const creationReview = maker.waitForResponse(
        (value) =>
          value.request().method() === 'POST' &&
          new URL(value.url()).pathname === notificationEndpointWorkbench,
      );
      await maker.getByRole('button', { name: 'Review endpoint creation', exact: true }).click();
      await expect(
        maker.getByRole('region', { name: 'Endpoint creation review', exact: true }),
      ).toBeVisible();
      const reviewedCreation = await creationReview;
      assert.equal(reviewedCreation.status(), 200);
      await endpointDenials(maker, checker, endpointView.parse(await reviewedCreation.json()));
      let failure;
      const capture = async (route) => {
        if (route.request().method() !== 'POST') return route.continue();
        try {
          const request = endpointCommand.options[1].parse(route.request().postDataJSON());
          assert.equal(request.destinationRef, destinationRef);
          original = { request };
          await save('endpoint-original-create.json', original); // Before any business effect.
          const response = await route.fetch();
          original.status = response.status();
          original.result = await response.json();
          await save('endpoint-original-create.json', original);
          assert.equal(
            original.status,
            202,
            'BLOCKED_NOTIFICATION_ENDPOINT_CREATE: public metadata admission/WebAuthn',
          );
          endpointView.parse(original.result);
          if (contextGate) {
            contextGate.record = original;
            contextGate.committed.resolve(original);
            await contextGate.release.promise;
            await route.fulfill({ response });
          }
        } catch (error) {
          failure = error;
          if (contextGate) {
            contextGate.failure = error;
            contextGate.committed.reject(error);
          }
          await route.abort('failed').catch(() => {});
        } finally {
          if (contextGate) contextGate.done.resolve();
          else await route.abort('failed').catch(() => {});
        }
      };
      await maker.route(`**${notificationEndpointWorkbench}`, capture, { times: 1 });
      await maker
        .getByRole('button', { name: 'Authenticate and create endpoint', exact: true })
        .click();
      if (contextGate) await finishEndpointFirstContext(maker, contextGate);
      else {
        await expect(
          maker
            .getByRole('region', { name: 'Notification endpoints', exact: true })
            .getByRole('alert'),
        ).toBeVisible();
        if (failure) throw failure;
        assert.ok(original?.result?.operation, 'CREATE did not reach a retained committed result');
        await inspectEndpointError(maker, 'create-response-lost');
        await maker.reload();
        await recoverEndpointAcrossLogout(maker, original);
      }
      await maker.getByRole('button', { name: 'Read operation endpoint', exact: true }).click();
      await expect(
        maker.getByRole('region', { name: 'Endpoint details', exact: true }),
      ).toContainText('DISABLED');
      await expect(
        maker.getByRole('region', { name: 'Original endpoint request recovery', exact: true }),
      ).toHaveCount(0);
    }
    // An incomplete/denied retained request is a classified resume prerequisite,
    // never grounds to create another endpoint or replace its original key.
    endpointCommand.options[1].parse(original.request);
    assert.equal(
      original.status,
      202,
      'BLOCKED_NOTIFICATION_ENDPOINT_CREATE: retained original needs causal recovery',
    );
    const result = endpointView.parse(original.result);
    assert.equal(result.kind, 'OPERATION');
    assert.equal(result.operation.actionIntentId, 'ACT-NOTIFICATION_ENDPOINTS_CREATE_RESOURCE-V1');
    assert.equal(result.operation.idempotencyKey, endpointRequestKey(original.request.requestKey));
    assert.equal(result.operation.state, 'SUCCEEDED');
    assert.equal(result.operation.truthState, 'SUCCESS');
    assert.equal(result.operation.revision, '1');
    if (destinationRef) assert.equal(original.request.destinationRef, destinationRef);
    const listed = await maker.request.get(`${origin}${notificationEndpointWorkbench}?view=LIST`);
    assert.equal(listed.status(), 200);
    const binding = endpointView.parse(await listed.json());
    const readback = await maker.request.get(
      `${origin}${notificationEndpointWorkbench}?${new URLSearchParams({
        view: 'OPERATION',
        actorKey: binding.actorKey,
        operationId: result.operation.operationId,
      })}`,
    );
    assert.equal(readback.status(), 200);
    assert.deepEqual((await readback.json()).operation, result.operation);
    const pendingHint = await maker.evaluate(() =>
      JSON.parse(sessionStorage.getItem('openpc:notification-endpoint-request:v1') ?? 'null'),
    );
    if (
      prior &&
      (!pendingHint || pendingHint.request?.requestKey === original.request.requestKey)
    ) {
      await maker
        .getByLabel('Existing endpoint operation ID', { exact: true })
        .fill(result.operation.operationId);
      await maker.getByRole('button', { name: 'Read endpoint operation', exact: true }).click();
      await expect(
        maker.getByRole('region', { name: 'Endpoint operation', exact: true }),
      ).toContainText(result.operation.operationId);
      await maker.getByRole('button', { name: 'Read operation endpoint', exact: true }).click();
      await expect(
        maker.getByRole('heading', { name: 'Endpoint details', exact: true }),
      ).toBeVisible();
      await expect(
        maker.getByRole('region', { name: 'Original endpoint request recovery', exact: true }),
      ).toHaveCount(0);
    }
    if (prior) {
      const proof = await readFile(
        join(artifacts, 'endpoint-first-CREATE-context-result.json'),
        'utf8',
      )
        .then(JSON.parse)
        .catch((error) => {
          if (error.code === 'ENOENT') return undefined;
          throw error;
        });
      if (proof) assert.equal(proof.operationId, result.operation.operationId);
      requireRetainedEndpointContext(proof, result.operation.operationId, endpointInflightMode);
      process.stdout.write(
        `OPENPC_NOTIFICATION_ENDPOINT_FIRST_CONTEXT|${proof?.state ?? 'OPEN'}|command=CREATE|retained=READ_ONLY|prior-result-preserved|no-resubmission\n`,
      );
    }
    process.stdout.write(
      `OPENPC_NOTIFICATION_ENDPOINT_CREATE_BROWSER|PASS|original=${prior ? 'REUSED_READ_ONLY' : 'CREATED_AND_RECOVERED'}|create-denials=${prior ? 'NOT_REEXECUTED' : 'PASSED'}|current-credential-rotation=OPEN\n`,
    );
    return result.operation.resourceRef;
  }
  async function runEndpointVerificationBrowser(maker, checker) {
    await preflightEndpointSql();
    const createdRef = await runEndpointCreationBrowser(maker, checker);
    const ref = createdRef ?? process.env.OPENPC_NOTIFICATION_ENDPOINT_REF;
    assert.match(
      ref ?? '',
      /^urn:openpc:resource:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
      'BLOCKED_NOTIFICATION_ENDPOINT_BROWSER: supported-owner endpoint or installed destination input required',
    );
    const resourceId = ref.slice(-36),
      file = join(artifacts, 'endpoint-original-verification.json');
    const prior = await readFile(file, 'utf8')
      .then(JSON.parse)
      .catch((error) => {
        if (error.code === 'ENOENT') return undefined;
        throw error;
      });
    const retainedReplacement = await readFile(
      join(artifacts, 'endpoint-original-update.json'),
      'utf8',
    )
      .then(JSON.parse)
      .catch((error) => {
        if (error.code === 'ENOENT') return undefined;
        throw error;
      });
    const updateEnabled =
      process.env.OPENPC_LOCAL_RUNTIME_NOTIFICATION_ENDPOINT_UPDATE_BROWSER === '1' ||
      !!retainedReplacement;
    const effects = async () =>
      (
        await pool.query(
          `select e.state,e.revision::text,e.verification_id,
      (select count(*)::int from control.notification_verification_attempt a where a.participant_id=e.participant_id and a.privacy_domain_id=e.privacy_domain_id and a.endpoint_id=e.endpoint_id) attempts,
      (select count(*)::int from control.notification_endpoint_verification v where v.participant_id=e.participant_id and v.endpoint_id=e.endpoint_id) verifications,
      (select count(*)::int from control.audit_occurrence a where a.participant_id=e.participant_id and a.aggregate_id=e.endpoint_id) receipts,
      (select count(*)::int from control.outbox_event o where o.participant_id=e.participant_id and o.aggregate_id=e.endpoint_id) events
      from control.notification_endpoint e where e.participant_id=$1 and e.privacy_domain_id=$2 and e.endpoint_id=$3`,
          [participantId, privacyDomainId, resourceId],
        )
      ).rows[0];
    const source = async () => {
      const rows = await pool.query(
        `select attempt_id,state,challenge_bytes,response_bytes,receipt_digest,attached_operation_id
       from control.notification_verification_attempt where participant_id=$1 and privacy_domain_id=$2 and endpoint_id=$3 and attached_operation_id=$4`,
        [participantId, privacyDomainId, resourceId, original.result.operation.operationId],
      );
      assert.equal(rows.rowCount, 1);
      return rows.rows[0];
    };
    const wait = (page, method = 'POST', view) => {
      const result = page.waitForResponse((value) => {
        const url = new URL(value.url());
        return (
          url.pathname === notificationEndpointWorkbench &&
          value.request().method() === method &&
          (method !== 'GET' || url.searchParams.get('view') === view)
        );
      });
      void result.catch(() => {});
      return result;
    };
    const read = async (page, query) => {
      const response = await page.request.get(
        `${origin}${notificationEndpointWorkbench}?${new URLSearchParams(query)}`,
      );
      assert.equal(
        response.status(),
        200,
        'BLOCKED_NOTIFICATION_ENDPOINT_BROWSER: real endpoint public read/actor admission',
      );
      assert.equal(response.headers()['cache-control'], 'no-store');
      return endpointView.parse(await response.json());
    };
    const select = async (page, selectedRef = ref) => {
      await page.getByLabel('Filter field', { exact: true }).selectOption('destinationRef');
      const bound = await read(page, { view: 'LIST' });
      const detail = await read(page, {
        view: 'DETAIL',
        actorKey: bound.actorKey,
        endpointRef: selectedRef,
      });
      assert.equal(detail.kind, 'DETAIL');
      endpointRecord.parse(detail.endpoint);
      await page.getByLabel('Filter value', { exact: true }).fill(detail.endpoint.destinationRef);
      const listed = wait(page, 'GET', 'LIST');
      await page.getByRole('button', { name: 'Refresh endpoints', exact: true }).click();
      assert.equal((await listed).status(), 200);
      const inspected = wait(page, 'GET', 'DETAIL');
      await page.getByRole('button', { name: `Inspect ${selectedRef}`, exact: true }).click();
      assert.equal((await inspected).status(), 200);
      await expect(
        page.getByRole('heading', { name: 'Endpoint details', exact: true }),
      ).toBeFocused();
      return detail;
    };
    async function runUnknownVerification() {
      const unknownRef = process.env.OPENPC_NOTIFICATION_ENDPOINT_UNKNOWN_REF;
      assert.match(
        unknownRef ?? '',
        /^urn:openpc:resource:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
        'BLOCKED_NOTIFICATION_ENDPOINT_UNKNOWN: separate supported-owner endpoint required',
      );
      assert.notEqual(unknownRef, ref, 'UNKNOWN must use an independent fresh business intent');
      const unknownId = unknownRef.slice(-36);
      const artifact = 'endpoint-original-unknown-verification.json';
      let retained = await readFile(join(artifacts, artifact), 'utf8')
        .then(JSON.parse)
        .catch((error) => {
          if (error.code === 'ENOENT') return undefined;
          throw error;
        });
      const snapshot = async () => {
        const values = await pool.query(
          `select e.state,e.revision::text,e.verification_id,
        (select count(*)::int from control.notification_endpoint_verification v where v.participant_id=e.participant_id and v.endpoint_id=e.endpoint_id) verifications,
        (select count(*)::int from control.audit_occurrence a where a.participant_id=e.participant_id and a.aggregate_id=e.endpoint_id) receipts,
        (select count(*)::int from control.outbox_event o where o.participant_id=e.participant_id and o.aggregate_id=e.endpoint_id) events
        from control.notification_endpoint e where e.participant_id=$1 and e.privacy_domain_id=$2 and e.endpoint_id=$3`,
          [participantId, privacyDomainId, unknownId],
        );
        assert.equal(values.rowCount, 1);
        return values.rows[0];
      };
      const attempts = async () =>
        (
          await pool.query(
            `select attempt_id,state,challenge_bytes,response_bytes,receipt_digest,attached_operation_id
      from control.notification_verification_attempt where participant_id=$1 and privacy_domain_id=$2 and endpoint_id=$3`,
            [participantId, privacyDomainId, unknownId],
          )
        ).rows;
      const noEffect = {
        state: 'DISABLED',
        revision: '1',
        verification_id: null,
        verifications: 0,
        receipts: 1,
        events: 1,
      };
      assert.deepEqual(await snapshot(), noEffect);
      const created = await pool.query(
        `select i.operation_id from control.idempotency_record i
      join control.audit_occurrence a on a.participant_id=i.participant_id and a.operation_id=i.operation_id
      where i.participant_id=$1 and i.privacy_domain_id=$2 and i.catalog_operation_id='CFG-OP-CREATE-NOTIFICATION-ENDPOINT'
      and i.terminal_state='COMMITTED' and a.aggregate_id=$3`,
        [participantId, privacyDomainId, unknownId],
      );
      assert.equal(created.rowCount, 1, 'UNKNOWN prerequisite must be a real signed CREATE');
      await maker.reload();
      const selected = await select(maker, unknownRef);
      const scope = {
        participantId,
        privacyDomainId,
        destinationRef: selected.endpoint.destinationRef,
      };
      // WeakMap branding requires the actual process-private external fixture.
      // No HTTP fault route, browser storage authority or fabricated proof exists.
      const stats = () => notificationRuntimeVerificationStats(notificationRuntime, scope);
      const assertUnknown = (status, problem) => {
        assert.equal(status, 409, 'BLOCKED_NOTIFICATION_ENDPOINT_UNKNOWN: retain original outcome');
        assert.equal(problem.code, 'PC-FACT-4001');
        assert.equal(problem.truthState, 'UNKNOWN');
      };
      if (!retained) {
        assert.deepEqual(await attempts(), []);
        assert.equal(
          await maker.evaluate(() =>
            sessionStorage.getItem('openpc:notification-endpoint-request:v1'),
          ),
          null,
          'Preserve unresolved original before a new UNKNOWN intent',
        );
        const before = stats();
        let interceptionError;
        const intercept = async (route) => {
          if (route.request().method() !== 'POST') return route.continue();
          try {
            retained = {
              request: endpointCommand.options[0].parse(route.request().postDataJSON()),
            };
            assert.equal(retained.request.endpointRef, unknownRef);
            await save(artifact, retained); // Persist original identity before external I/O.
            const upstream = await route.fetch();
            retained.status = upstream.status();
            retained.result = await upstream.json();
            await save(artifact, retained);
            assertUnknown(retained.status, retained.result);
            await route.fulfill({ response: upstream }); // Actual UNKNOWN, never a manufactured result.
          } catch (error) {
            interceptionError = error;
            await route.abort('failed');
          }
        };
        await maker.route(`**${notificationEndpointWorkbench}`, intercept, { times: 1 });
        try {
          await withNotificationRuntimeLostAck(notificationRuntime, scope, async () => {
            await maker
              .getByLabel('Verification reason', { exact: true })
              .fill('Retain the original verification when the external acknowledgment is lost.');
            const pending = wait(maker);
            await maker.getByRole('button', { name: 'Verify endpoint', exact: true }).click();
            const outcome = await pending.catch((error) => {
              throw interceptionError ?? error;
            });
            if (interceptionError) throw interceptionError;
            assertUnknown(outcome.status(), await outcome.json());
          });
        } finally {
          await maker.unroute(`**${notificationEndpointWorkbench}`, intercept);
        }
        assert.deepEqual(stats(), { calls: before.calls + 1, receipts: before.receipts + 1 });
      }
      endpointCommand.options[0].parse(retained.request);
      assert.equal(retained.request.endpointRef, unknownRef);
      assertUnknown(retained.status, retained.result);
      const sealed = await attempts();
      assert.equal(sealed.length, 1);
      assert.ok(['DISPATCHED', 'UNKNOWN'].includes(sealed[0].state));
      assert.equal(sealed[0].attached_operation_id, null);
      assert.equal(sealed[0].response_bytes, null);
      assert.equal(sealed[0].receipt_digest, null);
      const beforeReplay = stats();
      const recover = async () => {
        await maker.reload();
        const hint = await maker.evaluate(() =>
          JSON.parse(sessionStorage.getItem('openpc:notification-endpoint-request:v1') ?? 'null'),
        );
        assert.deepEqual(
          hint?.request,
          retained.request,
          'BLOCKED_NOTIFICATION_ENDPOINT_UNKNOWN: original authorized browser recovery required',
        );
        const pending = wait(maker);
        await maker
          .getByRole('button', { name: 'Recover original verification', exact: true })
          .click();
        const result = await pending;
        assert.deepEqual(result.request().postDataJSON(), retained.request);
        assertUnknown(result.status(), await result.json());
        const alert = maker
          .getByRole('region', { name: 'Notification endpoints', exact: true })
          .getByRole('alert');
        await expect(alert).toBeFocused();
        await expect(alert).toContainText('outcome is unknown');
        const current = await attempts();
        assert.equal(current.length, 1);
        assert.ok(['DISPATCHED', 'UNKNOWN'].includes(current[0].state));
        assert.deepEqual({ ...current[0], state: sealed[0].state }, sealed[0]);
        assert.deepEqual(await snapshot(), noEffect);
        assert.deepEqual(stats(), beforeReplay, 'Original UNKNOWN must never resend');
      };
      await recover();
      await restartBrowserServices();
      await expect
        .poll(
          async () => {
            try {
              return (
                await maker.request.get(`${origin}${notificationEndpointWorkbench}?view=LIST`)
              ).status();
            } catch {
              return 0;
            }
          },
          { timeout: 30000, intervals: [250, 500, 1000] },
        )
        .toBe(200);
      await recover();
      process.stdout.write(
        'OPENPC_NOTIFICATION_ENDPOINT_UNKNOWN_BROWSER|PASS|real-lost-ack|original-identity|no-resend|no-activation|restart|full-quarantine=OPEN\n',
      );
    }
    for (const page of [maker, checker]) {
      await page.goto(`${origin}/home/session?view=notification-endpoints`);
      await expect(
        page.getByRole('heading', { name: 'Notification endpoints', exact: true }),
      ).toBeVisible();
    }
    async function replaceAndVerify() {
      let updated = retainedReplacement;
      const verified = await readFile(
        join(artifacts, 'endpoint-replacement-verification.json'),
        'utf8',
      )
        .then(JSON.parse)
        .catch((error) => {
          if (error.code === 'ENOENT') return undefined;
          throw error;
        });
      assert.ok(!verified || updated, 'Orphan replacement verification must be reconciled');
      const settleKnown = async (entry) => {
        assert.equal(
          entry.status,
          202,
          'Retained original replacement phase requires causal recovery',
        );
        const result = endpointView.parse(entry.result);
        assert.equal(result.kind, 'OPERATION');
        assert.equal(result.operation.resourceRef, ref);
        assert.equal(result.operation.state, 'SUCCEEDED');
        assert.equal(result.operation.truthState, 'SUCCESS');
        assert.equal(result.operation.idempotencyKey, endpointRequestKey(entry.request.requestKey));
        const binding = await read(maker, { view: 'LIST' });
        const known = await read(maker, {
          view: 'OPERATION',
          actorKey: binding.actorKey,
          operationId: result.operation.operationId,
        });
        assert.deepEqual(known.operation, result.operation);
        // Read the known ID in the rendered UI; never manufacture a browser hint.
        await maker
          .getByLabel('Existing endpoint operation ID', { exact: true })
          .fill(result.operation.operationId);
        const operationRead = wait(maker, 'GET', 'OPERATION');
        await maker.getByRole('button', { name: 'Read endpoint operation', exact: true }).click();
        assert.equal((await operationRead).status(), 200);
        const detailRead = wait(maker, 'GET', 'DETAIL');
        await maker.getByRole('button', { name: 'Read operation endpoint', exact: true }).click();
        const detail = endpointView.parse(await (await detailRead).json());
        await expect(
          maker.getByRole('region', { name: 'Original endpoint request recovery', exact: true }),
        ).toHaveCount(0);
        return detail;
      };
      if (!updated) {
        const contextGate = await prepareEndpointContext(maker);
        const before = await select(maker);
        assert.equal(before.endpoint.state, 'ACTIVE');
        assert.equal(before.endpoint.revision, '2');
        const available = await read(maker, {
          view: 'REPLACEMENTS',
          actorKey: before.actorKey,
          endpointRef: ref,
        });
        assert.equal(available.kind, 'REPLACEMENTS');
        assert.equal(available.choices.revision, before.endpoint.revision);
        const configuredDigest = process.env.OPENPC_NOTIFICATION_ENDPOINT_REPLACEMENT_DIGEST;
        const configuredDestination =
          process.env.OPENPC_NOTIFICATION_ENDPOINT_REPLACEMENT_DESTINATION_REF;
        const candidates = available.choices.items.filter((item) =>
          configuredDigest
            ? item.replacementDigest === configuredDigest
            : configuredDestination
              ? item.destinationRef === configuredDestination
              : item.destinationRef !== before.endpoint.destinationRef ||
                item.channel !== before.endpoint.channel,
        );
        assert.equal(
          candidates.length,
          1,
          'BLOCKED_NOTIFICATION_ENDPOINT_REPLACEMENT: one installed replacement must be selected by its public digest/destination',
        );
        const chosen = candidates[0];
        const prepare = async (page) => {
          const current = await select(page);
          assert.equal(current.endpoint.revision, '2');
          await page.getByRole('button', { name: 'Load replacement choices', exact: true }).click();
          await page
            .getByLabel('Endpoint replacement', { exact: true })
            .selectOption(chosen.replacementDigest);
          await page
            .getByLabel('Replacement reason', { exact: true })
            .fill('Replace the selected installed endpoint binding.');
          const reviewed = wait(page);
          await page
            .getByRole('button', { name: 'Review endpoint replacement', exact: true })
            .click();
          const response = await reviewed;
          assert.equal(response.status(), 200);
          await expect(
            page.getByRole('region', { name: 'Endpoint replacement review', exact: true }),
          ).toBeVisible();
          return endpointView.parse(await response.json());
        };
        const checkerPending = await checker.evaluate(() =>
          JSON.parse(sessionStorage.getItem('openpc:notification-endpoint-request:v1') ?? 'null'),
        );
        if (checkerPending) {
          assert.equal(
            checkerPending.uncertain,
            false,
            'Uncertain checker request cannot be replaced',
          );
          assert.equal(checkerPending.operationId, undefined);
          assert.equal(checkerPending.request.endpointRef, ref);
          const refreshed = wait(checker, 'GET', 'LIST');
          await checker
            .getByRole('button', { name: 'Dismiss rejected request and refresh', exact: true })
            .click();
          assert.equal((await refreshed).status(), 200);
        }
        const inspected = await effects();
        const reviewedUpdate = await prepare(maker);
        await prepare(checker);
        await endpointDenials(maker, checker, reviewedUpdate);
        assert.deepEqual(
          await effects(),
          inspected,
          'Choice/review reads cannot replace or verify an endpoint',
        );
        let failure;
        const capture = async (route) => {
          if (route.request().method() !== 'POST') return route.continue();
          try {
            updated = { request: endpointCommand.options[2].parse(route.request().postDataJSON()) };
            assert.equal(updated.request.replacementDigest, chosen.replacementDigest);
            await save('endpoint-original-update.json', updated);
            const response = await route.fetch();
            updated.status = response.status();
            updated.result = await response.json();
            await save('endpoint-original-update.json', updated);
            assert.equal(
              updated.status,
              202,
              'Real public replacement must commit before response-loss recovery',
            );
            if (contextGate) {
              contextGate.record = updated;
              contextGate.committed.resolve(updated);
              await contextGate.release.promise;
              await route.fulfill({ response });
            }
          } catch (error) {
            failure = error;
            if (contextGate) {
              contextGate.failure = error;
              contextGate.committed.reject(error);
            }
            await route.abort('failed').catch(() => {});
          } finally {
            if (contextGate) contextGate.done.resolve();
            else await route.abort('failed').catch(() => {});
          }
        };
        await maker.route(`**${notificationEndpointWorkbench}`, capture, { times: 1 });
        await maker
          .getByRole('button', { name: 'Authenticate and replace endpoint', exact: true })
          .click();
        if (contextGate) await finishEndpointFirstContext(maker, contextGate);
        else {
          await expect(
            maker
              .getByRole('region', { name: 'Notification endpoints', exact: true })
              .getByRole('alert'),
          ).toBeVisible();
          if (failure) throw failure;
          assert.ok(
            updated?.result?.operation,
            'Replacement authentication/mutation did not reach its owner',
          );
          await inspectEndpointError(maker, 'update-response-lost');
          await maker.reload();
          await recoverEndpointAcrossLogout(maker, updated);
        }
        const current = await settleKnown(updated);
        assert.equal(current.endpoint.state, 'DISABLED');
        assert.equal(current.endpoint.revision, '3');
        assert.equal(current.endpoint.destinationRef, chosen.destinationRef);
        assert.equal(current.endpoint.channel, chosen.channel);
        const stable = await effects();
        const stale = wait(checker);
        await checker
          .getByRole('button', { name: 'Authenticate and replace endpoint', exact: true })
          .click();
        const denied = await stale;
        await save('endpoint-stale-replacement.json', {
          request: denied.request().postDataJSON(),
          status: denied.status(),
        });
        assert.equal(denied.status(), 412);
        await inspectEndpointError(checker, 'stale-replacement');
        assert.deepEqual(
          await effects(),
          stable,
          'Stale replacement must preserve original signed effects',
        );
      } else {
        endpointCommand.options[2].parse(updated.request);
        assert.equal(updated.request.endpointRef, ref);
        const proof = await readFile(
          join(artifacts, 'endpoint-first-UPDATE-context-result.json'),
          'utf8',
        )
          .then(JSON.parse)
          .catch((error) => {
            if (error.code === 'ENOENT') return undefined;
            throw error;
          });
        if (proof) assert.equal(proof.operationId, updated.result.operation.operationId);
        process.stdout.write(
          `OPENPC_NOTIFICATION_ENDPOINT_FIRST_CONTEXT|${proof?.state ?? 'OPEN'}|command=UPDATE|retained=READ_ONLY|prior-result-preserved|no-resubmission\n`,
        );
        // A retained later verification can own the UI hint. Inspect its matching
        // operation below rather than overwriting it with an earlier update.
        if (!verified) await settleKnown(updated);
        else {
          const binding = await read(maker, { view: 'LIST' });
          const known = await read(maker, {
            view: 'OPERATION',
            actorKey: binding.actorKey,
            operationId: updated.result.operation.operationId,
          });
          assert.deepEqual(known.operation, updated.result.operation);
        }
        requireRetainedEndpointContext(
          proof,
          updated.result.operation.operationId,
          endpointInflightMode,
        );
      }
      assert.equal(updated.status, 202);
      assert.equal(
        updated.result.operation.actionIntentId,
        'ACT-NOTIFICATION_ENDPOINTS_UPDATE_RESOURCE-V1',
      );
      assert.equal(updated.result.operation.revision, '3');
      let reverified = verified;
      if (!reverified) {
        const selected = await select(maker);
        assert.equal(selected.endpoint.state, 'DISABLED');
        assert.equal(selected.endpoint.revision, '3');
        let failure;
        const capture = async (route) => {
          if (route.request().method() !== 'POST') return route.continue();
          try {
            reverified = {
              request: endpointCommand.options[0].parse(route.request().postDataJSON()),
            };
            assert.equal(reverified.request.expectedRevision, '3');
            await save('endpoint-replacement-verification.json', reverified);
            const response = await route.fetch();
            reverified.status = response.status();
            reverified.result = await response.json();
            await save('endpoint-replacement-verification.json', reverified);
            assert.equal(
              reverified.status,
              202,
              'Replacement requires its own real nondelivery verification',
            );
            await route.fulfill({ response });
          } catch (error) {
            failure = error;
            await route.abort('failed');
          }
        };
        await maker.route(`**${notificationEndpointWorkbench}`, capture, { times: 1 });
        await maker
          .getByLabel('Verification reason', { exact: true })
          .fill('Verify the exact replacement binding.');
        await maker.getByRole('button', { name: 'Verify endpoint', exact: true }).click();
        await expect.poll(() => !!failure || !!reverified?.status).toBe(true);
        if (failure) throw failure;
      }
      const final = await settleKnown(reverified);
      assert.equal(final.endpoint.state, 'ACTIVE');
      assert.equal(final.endpoint.revision, '4');
      assert.equal(reverified.result.operation.actionIntentId, 'ACT-NOTIFICATION_UPDATE_VERIFY-V1');
      assert.equal(reverified.result.operation.revision, '4');
      assert.notEqual(
        reverified.result.operation.operationId,
        original.result.operation.operationId,
      );
      return { updated, reverified };
    }
    let original = prior;
    if (!original) {
      const before = await effects();
      assert.deepEqual(
        before,
        {
          state: 'DISABLED',
          revision: '1',
          verification_id: null,
          attempts: 0,
          verifications: 0,
          receipts: 1,
          events: 1,
        },
        'BLOCKED_NOTIFICATION_ENDPOINT_BROWSER: fresh supported-owner CREATE prerequisite',
      );
      const created = await pool.query(
        `select i.operation_id from control.idempotency_record i join control.audit_occurrence a on a.participant_id=i.participant_id and a.operation_id=i.operation_id
       where i.participant_id=$1 and i.privacy_domain_id=$2 and i.catalog_operation_id='CFG-OP-CREATE-NOTIFICATION-ENDPOINT'
       and i.terminal_state='COMMITTED' and a.aggregate_id=$3`,
        [participantId, privacyDomainId, resourceId],
      );
      assert.equal(
        created.rowCount,
        1,
        'BLOCKED_NOTIFICATION_ENDPOINT_BROWSER: original signed CREATE owner result missing',
      );
      const selected = await select(maker);
      const stale = await select(checker);
      assert.deepEqual(await effects(), before, 'Inspection must not allocate a verification');
      const anonymous = await fetch(`${origin}${notificationEndpointWorkbench}?view=LIST`);
      assert.equal(anonymous.status, 404);
      const denied = await maker.request.get(
        `${origin}${notificationEndpointWorkbench}?${new URLSearchParams({ view: 'DETAIL', actorKey: stale.actorKey, endpointRef: ref })}`,
      );
      assert.equal(denied.status(), 404);
      const pending = await maker.evaluate(() =>
        sessionStorage.getItem('openpc:notification-endpoint-request:v1'),
      );
      assert.equal(
        pending,
        null,
        'BLOCKED_NOTIFICATION_ENDPOINT_BROWSER: preserve unresolved original before a new intent',
      );
      let interceptionError;
      await maker.route(
        `**${notificationEndpointWorkbench}`,
        async (route) => {
          if (route.request().method() !== 'POST') return route.continue();
          // Real upstream effect, then intentionally discard only its browser reply.
          try {
            original = {
              request: endpointCommand.options[0].parse(route.request().postDataJSON()),
            };
            await save('endpoint-original-verification.json', original);
            const response = await route.fetch();
            original.status = response.status();
            original.result = await response.json();
            await save('endpoint-original-verification.json', original);
            assert.equal(
              response.status(),
              202,
              'BLOCKED_NOTIFICATION_ENDPOINT_BROWSER: actual public VERIFY composition',
            );
            endpointView.parse(original.result);
          } catch (error) {
            interceptionError = error;
          } finally {
            await route.abort('failed');
          }
        },
        { times: 1 },
      );
      await maker
        .getByLabel('Verification reason', { exact: true })
        .fill('Verify the installed endpoint through its real signed owner.');
      await maker.getByRole('button', { name: 'Verify endpoint', exact: true }).click();
      await expect(
        maker
          .getByRole('region', { name: 'Notification endpoints', exact: true })
          .getByRole('alert'),
      ).toBeVisible();
      if (interceptionError) throw interceptionError;
      assert.ok(original?.result?.operation, 'Original response must be retained before recovery');
      assert.equal(original.request.endpointRef, ref);
      assert.equal(original.request.expectedRevision, selected.endpoint.revision);
      assert.equal(original.request.etag, selected.etag);
      await maker.reload();
      const recovered = wait(maker);
      await maker
        .getByRole('button', { name: 'Recover original verification', exact: true })
        .click();
      const response = await recovered;
      assert.equal(response.status(), 202);
      assert.deepEqual(response.request().postDataJSON(), original.request);
      assert.deepEqual(endpointView.parse(await response.json()), original.result);
      const effectRead = wait(maker, 'GET', 'DETAIL');
      await maker.getByRole('button', { name: 'Read operation endpoint', exact: true }).click();
      const current = endpointView.parse(await (await effectRead).json());
      assert.equal(current.endpoint.state, 'ACTIVE');
      assert.equal(current.endpoint.revision, '2');
      await checker
        .getByLabel('Verification reason', { exact: true })
        .fill('Reject the retained predecessor revision.');
      const staleReply = wait(checker);
      await checker.getByRole('button', { name: 'Verify endpoint', exact: true }).click();
      const deniedVerification = await staleReply;
      await save('endpoint-stale-verification.json', {
        request: deniedVerification.request().postDataJSON(),
        status: deniedVerification.status(),
      });
      assert.equal(deniedVerification.status(), 412);
      await expect(
        checker
          .getByRole('region', { name: 'Notification endpoints', exact: true })
          .getByRole('alert'),
      ).toBeFocused();
    } else {
      endpointCommand.options[0].parse(original.request);
      endpointView.parse(original.result);
      assert.equal(original.request.endpointRef, ref);
      // Retained acceptance resumes with readback only. It never rewrites the
      // browser hint or resubmits a consumed effect merely to obtain another pass.
      const pending = await maker.evaluate(() =>
        JSON.parse(sessionStorage.getItem('openpc:notification-endpoint-request:v1') ?? 'null'),
      );
      if (pending?.request?.requestKey === original.request.requestKey) {
        assert.deepEqual(pending.request, original.request);
        await maker
          .getByLabel('Existing endpoint operation ID', { exact: true })
          .fill(original.result.operation.operationId);
        const operationRead = wait(maker, 'GET', 'OPERATION');
        await maker.getByRole('button', { name: 'Read endpoint operation', exact: true }).click();
        assert.equal((await operationRead).status(), 200);
        const detailRead = wait(maker, 'GET', 'DETAIL');
        await maker.getByRole('button', { name: 'Read operation endpoint', exact: true }).click();
        assert.equal((await detailRead).status(), 200);
        await expect(
          maker.getByRole('region', { name: 'Original endpoint request recovery', exact: true }),
        ).toHaveCount(0);
      }
      await select(maker);
    }
    assert.equal(original.result.kind, 'OPERATION');
    const operation = original.result.operation;
    assert.equal(operation.idempotencyKey, endpointRequestKey(original.request.requestKey));
    assert.equal(operation.resourceRef, ref);
    assert.equal(operation.state, 'SUCCEEDED');
    assert.equal(operation.truthState, 'SUCCESS');
    const attached = await source();
    assert.equal(attached.state, 'ATTACHED');
    assert.equal(attached.attached_operation_id, operation.operationId);
    if (!retainedReplacement)
      assert.deepEqual(await effects(), {
        state: 'ACTIVE',
        revision: '2',
        verification_id: attached.attempt_id,
        attempts: 1,
        verifications: 1,
        receipts: 2,
        events: 2,
      });
    const progression = updateEnabled ? await replaceAndVerify() : undefined;
    const finalSource = progression
      ? (
          await pool.query(
            `select attempt_id,state,challenge_bytes,response_bytes,receipt_digest,attached_operation_id
    from control.notification_verification_attempt where participant_id=$1 and privacy_domain_id=$2 and endpoint_id=$3 and attached_operation_id=$4`,
            [
              participantId,
              privacyDomainId,
              resourceId,
              progression.reverified.result.operation.operationId,
            ],
          )
        ).rows
      : [attached];
    assert.equal(finalSource.length, 1);
    assert.equal(finalSource[0].state, 'ATTACHED');
    const after = await effects();
    assert.deepEqual(after, {
      state: 'ACTIVE',
      revision: progression ? '4' : '2',
      verification_id: finalSource[0].attempt_id,
      attempts: progression ? 2 : 1,
      verifications: progression ? 2 : 1,
      receipts: progression ? 4 : 2,
      events: progression ? 4 : 2,
    });
    const signedSnapshot = async () => ({
      receipts: (
        await pool.query(
          `select a.*,k.public_key_spki_der from control.audit_occurrence a
      join control.business_signing_key k using(participant_id,privacy_domain_id,signer_id)
      where a.participant_id=$1 and a.privacy_domain_id=$2 and a.aggregate_type='notification-endpoint'
        and a.aggregate_id=$3 order by a.after_revision`,
          [participantId, privacyDomainId, resourceId],
        )
      ).rows,
      events: (
        await pool.query(
          `select event_id,receipt_id,correlation_id,proof_kind,sequence_namespace,business_sequence,payload_cbor
      from control.outbox_event where participant_id=$1 and privacy_domain_id=$2
        and aggregate_type='notification-endpoint' and aggregate_id=$3 order by business_sequence`,
          [participantId, privacyDomainId, resourceId],
        )
      ).rows,
    });
    const sealed = await signedSnapshot();
    assert.equal(sealed.receipts.length, progression ? 4 : 2);
    assert.equal(sealed.events.length, progression ? 4 : 2);
    for (const [index, row] of sealed.receipts.entries()) {
      assert.ok(
        kernel.verifyReceiptCose(row.public_key_spki_der, row.receipt_cbor, row.cose_sign1),
      );
      const receipt = kernel.decodeAdmittedReceipt(row.receipt_cbor);
      assert.equal(receipt.participantId, participantId);
      assert.equal(receipt.privacyDomainId, privacyDomainId);
      assert.equal(receipt.aggregateType, 'notification-endpoint');
      assert.equal(receipt.aggregateId, resourceId);
      assert.equal(receipt.before.revision, BigInt(index));
      assert.equal(receipt.after.revision, BigInt(index + 1));
      assert.equal(receipt.operationId, row.operation_id);
      assert.equal(
        receipt.actionIntentId,
        index === 0
          ? 'ACT-NOTIFICATION_ENDPOINTS_CREATE_RESOURCE-V1'
          : index === 2
            ? 'ACT-NOTIFICATION_ENDPOINTS_UPDATE_RESOURCE-V1'
            : 'ACT-NOTIFICATION_UPDATE_VERIFY-V1',
      );
      if (index === 1) assert.equal(receipt.operationId, operation.operationId);
      if (index === 2)
        assert.equal(receipt.operationId, progression.updated.result.operation.operationId);
      if (index === 3)
        assert.equal(receipt.operationId, progression.reverified.result.operation.operationId);
      const hash = (bytes) => createHash('sha256').update(bytes).digest();
      assert.deepEqual(hash(row.before_state_preimage), receipt.before.stateDigest);
      assert.deepEqual(hash(row.after_state_preimage), receipt.after.stateDigest);
      assert.deepEqual(hash(row.receipt_cbor), row.receipt_digest);
      const events = sealed.events.filter((event) => event.receipt_id === row.receipt_id);
      assert.equal(events.length, 1);
      assert.equal(receipt.outboxEvents.length, 1);
      assert.equal(events[0].event_id, receipt.outboxEvents[0].eventId);
      assert.equal(events[0].correlation_id, receipt.operationId);
      assert.equal(events[0].proof_kind, 'BUSINESS_RECEIPT_REFERENCE');
      assert.equal(events[0].sequence_namespace, 'CONTROL_BUSINESS_TRANSITION_V1');
      assert.equal(BigInt(events[0].business_sequence), receipt.outboxEvents[0].aggregateSequence);
      assert.deepEqual(hash(events[0].payload_cbor), receipt.outboxEvents[0].payloadDigest);
    }
    const bound = await read(maker, { view: 'LIST' });
    const previous = await read(maker, {
      view: 'DETAIL',
      actorKey: bound.actorKey,
      endpointRef: ref,
    });
    const known = await read(maker, {
      view: 'OPERATION',
      actorKey: bound.actorKey,
      operationId: operation.operationId,
    });
    assert.deepEqual(known.operation, operation);
    await restartBrowserServices();
    await expect
      .poll(
        async () => {
          try {
            return (
              await maker.request.get(`${origin}${notificationEndpointWorkbench}?view=LIST`)
            ).status();
          } catch {
            return 0;
          }
        },
        { timeout: 30000, intervals: [250, 500, 1000] },
      )
      .toBe(200);
    assert.deepEqual(
      await read(maker, { view: 'DETAIL', actorKey: bound.actorKey, endpointRef: ref }),
      previous,
    );
    assert.deepEqual(
      (
        await read(maker, {
          view: 'OPERATION',
          actorKey: bound.actorKey,
          operationId: operation.operationId,
        })
      ).operation,
      operation,
    );
    assert.deepEqual(await source(), attached);
    if (progression)
      assert.deepEqual(
        (
          await pool.query(
            `select attempt_id,state,challenge_bytes,response_bytes,receipt_digest,attached_operation_id
    from control.notification_verification_attempt where participant_id=$1 and privacy_domain_id=$2 and endpoint_id=$3 and attached_operation_id=$4`,
            [
              participantId,
              privacyDomainId,
              resourceId,
              progression.reverified.result.operation.operationId,
            ],
          )
        ).rows,
        finalSource,
      );
    assert.deepEqual(await effects(), after);
    assert.deepEqual(await signedSnapshot(), sealed);
    await maker.reload();
    await select(maker);
    await maker.getByLabel('Filter field', { exact: true }).focus();
    await maker.keyboard.press('Tab');
    await expect(maker.getByLabel('Filter value', { exact: true })).toBeFocused();
    for (const width of [1440, 360]) {
      await maker.setViewportSize({ width, height: 1000 });
      assert.deepEqual(
        (
          await new AxeBuilder({ page: maker })
            .withTags(['wcag2a', 'wcag2aa', 'wcag21aa'])
            .analyze()
        ).violations,
        [],
      );
      assert.ok(await maker.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
      await maker.screenshot({
        path: join(artifacts, `notification-endpoint-${width}.png`),
        fullPage: true,
      });
    }
    await maker.evaluate(() => window.dispatchEvent(new Event('blur')));
    await expect(maker.getByRole('heading', { name: 'Endpoint details', exact: true })).toHaveCount(
      0,
    );
    const unknownEnabled =
      process.env.OPENPC_LOCAL_RUNTIME_NOTIFICATION_ENDPOINT_UNKNOWN_BROWSER === '1';
    if (unknownEnabled) await runUnknownVerification();
    process.stdout.write(
      `OPENPC_NOTIFICATION_ENDPOINT_BROWSER|PASS|scope=${createdRef ? 'create-verify' : 'existing-endpoint-verify'}|original=${prior ? 'REUSED_READ_ONLY' : 'VERIFIED_AND_RECOVERED'}|restart|keyboard|axe|reflow|visual-inspection=PENDING|update=${progression ? 'REPLACED_AND_REVERIFIED' : 'OPEN'}|unknown=${unknownEnabled ? 'ORIGINAL_RECOVERY_PASSED' : 'OPEN'}|full-create-denials-quarantine=OPEN\n`,
    );
  }
  try {
    await withTransactionBrowser(
      { secretRoot, evidenceRoot: artifacts, artifacts, privacyDomainId, reuseSessions: true },
      async ({ maker, checker }) => {
        for (const page of [maker, checker]) {
          await page.getByRole('link', { name: 'Notifications', exact: true }).click();
          await expect(
            page.getByRole('heading', { name: 'Notifications', exact: true }),
          ).toBeVisible();
          await settleRetainedBrowserRequest(page);
          await expect(
            page.getByRole('button', { name: 'Create notification', exact: true }),
          ).toBeEnabled();
        }
        const prior = await readFile(join(artifacts, 'original-create.json'), 'utf8').catch(
          (error) => {
            if (error.code === 'ENOENT') return null;
            throw error;
          },
        );
        let committed = prior ? JSON.parse(prior) : undefined;
        const priorAcknowledgement = await readFile(
          join(artifacts, 'original-acknowledgement.json'),
          'utf8',
        ).catch((error) => {
          if (error.code === 'ENOENT') return null;
          throw error;
        });
        let acknowledged = priorAcknowledgement ? JSON.parse(priorAcknowledgement) : undefined;

        if (committed) {
          assert.ok(acknowledged?.result?.operation, 'NOTIFICATION_ORIGINAL_PARTIAL_BLOCKED');
          await readKnownOperation(maker, committed);
          await readKnownOperation(maker, acknowledged);
          assert.equal(
            acknowledged.request.notificationRef,
            committed.result.operation.resourceRef,
          );
          await runPopulatedMetadata(
            maker,
            checker,
            committed,
            acknowledged,
            committed.result.operation.resourceRef,
          );
          process.stdout.write(
            'OPENPC_NOTIFICATION_BROWSER|PASS|original=REUSED_READ_ONLY|populated-metadata=26|visual-inspection=PENDING|delivery=OPEN\n',
          );
          if (process.env.OPENPC_LOCAL_RUNTIME_NOTIFICATION_ENDPOINT_BROWSER === '1')
            await runEndpointVerificationBrowser(maker, checker);
          return;
        }

        assert.equal(acknowledged, undefined, 'NOTIFICATION_ORPHAN_ACK_BLOCKED');
        const messageKey =
          committed?.request.messageKey ??
          `evidence.export.completed.${randomBytes(6).toString('hex')}`;
        // Validate all currently available form selectors before any effect.
        for (const label of ['Severity', 'Filter field', 'Sort'])
          await expect(
            maker.getByRole('combobox', { name: new RegExp(`^${label}`, 'u') }),
          ).toHaveCount(1);
        await maker.getByRole('combobox', { name: /^Severity/u }).selectOption('WARNING');
        await maker.getByLabel('Message key', { exact: true }).fill(messageKey);
        await maker
          .getByLabel('Reason', { exact: true })
          .fill('Record completion metadata for the selected evidence export.');
        let interceptionError;
        const loseResponse = async (route) => {
          if (route.request().method() !== 'POST') return route.continue();
          try {
            const actual = await route.fetch();
            assert.equal(
              actual.status(),
              202,
              'Real metadata owner must commit before response loss',
            );
            committed = { request: route.request().postDataJSON(), result: await actual.json() };
            await save('original-create.json', committed);
          } catch (error) {
            interceptionError = error;
          }
          await route.abort('failed');
        };
        await maker.route(`**${endpoint}`, loseResponse);
        await maker.getByRole('button', { name: 'Create notification', exact: true }).click();
        await expect(
          maker.getByRole('region', { name: 'Notifications', exact: true }).getByRole('alert'),
        ).toContainText('The response is unavailable.');
        await maker.unroute(`**${endpoint}`, loseResponse);
        if (interceptionError) throw interceptionError;
        assert.ok(committed);
        await expect(
          maker.getByRole('button', { name: 'Create notification', exact: true }),
        ).toBeDisabled();
        // Reload preserves the original request identity without inventing authority.
        await maker.reload();
        await expect(
          maker.getByRole('button', { name: 'Recover original result', exact: true }),
        ).toBeEnabled();
        const replayPromise = response(maker);
        await maker.getByRole('button', { name: 'Recover original result', exact: true }).click();
        const replay = await replayPromise;
        assert.equal(replay.status(), 202);
        assert.deepEqual(replay.request().postDataJSON(), committed.request);
        assert.deepEqual(await replay.json(), committed.result);
        const readPromise = response(maker, 'GET', 'DETAIL');
        await maker
          .getByRole('button', { name: 'Read operation notification', exact: true })
          .click();
        const initial = await (await readPromise).json();
        assert.equal(initial.notification.state, acknowledged ? 'ACKNOWLEDGED' : 'UNREAD');
        assert.equal(initial.notification.revision, acknowledged ? '2' : '1');
        const ref = initial.notification.notificationId;
        await expect(
          maker.getByRole('region', { name: 'Original request recovery', exact: true }),
        ).toHaveCount(0);
        const counts = async () =>
          (
            await pool.query(
              `select
      (select count(*)::int from control.notification where participant_id=$1 and notification_id=$2) items,
      (select count(*)::int from control.audit_occurrence where participant_id=$1 and aggregate_type='notification' and aggregate_id=$2) receipts,
      (select count(*)::int from control.outbox_event where participant_id=$1 and aggregate_type='notification' and aggregate_id=$2) events`,
              [participantId, ref.slice(-36)],
            )
          ).rows[0];
        assert.deepEqual(await counts(), { items: 1, receipts: 1, events: 1 });
        // Both actors read revision 1; inspection is not an acknowledgement.
        await checker.getByRole('button', { name: 'Refresh notifications', exact: true }).click();
        const stale = await inspect(checker, messageKey);
        assert.deepEqual(stale.notification, initial.notification);
        assert.deepEqual(await counts(), { items: 1, receipts: 1, events: 1 });
        await maker
          .getByLabel('Acknowledgement reason', { exact: true })
          .fill('Reviewed the completed export metadata.');
        const ackPromise = response(maker);
        await maker.getByRole('button', { name: 'Acknowledge notification', exact: true }).click();
        const ackResponse = await ackPromise;
        assert.equal(ackResponse.status(), 202);
        acknowledged = {
          request: ackResponse.request().postDataJSON(),
          result: await ackResponse.json(),
        };
        await save('original-acknowledgement.json', acknowledged);
        await maker
          .getByRole('button', { name: 'Read operation notification', exact: true })
          .click();
        await expect(
          maker.getByText('Current metadata state: ACKNOWLEDGED.', { exact: true }),
        ).toBeVisible();
        await checker
          .getByLabel('Acknowledgement reason', { exact: true })
          .fill('Attempt to acknowledge the stale displayed revision.');
        const stalePromise = response(checker);
        await checker
          .getByRole('button', { name: 'Acknowledge notification', exact: true })
          .click();
        const rejected = await stalePromise;
        assert.equal(rejected.status(), 412);
        await save('original-stale-request.json', rejected.request().postDataJSON());
        await expect(
          checker.getByRole('region', { name: 'Notifications', exact: true }).getByRole('alert'),
        ).toContainText('selected revision is stale');
        await expect(
          checker.getByRole('region', { name: 'Notifications', exact: true }).getByRole('alert'),
        ).toBeFocused();
        assert.deepEqual(await counts(), { items: 1, receipts: 2, events: 2 });
        await checker
          .getByRole('button', { name: 'Dismiss rejected request and refresh', exact: true })
          .click();
        assert.equal((await inspect(checker, messageKey)).notification.state, 'ACKNOWLEDGED');
        const binding = await current(maker, { view: 'LIST' });
        const forged = await maker.request.get(
          `${origin}${endpoint}?${new URLSearchParams({ view: 'DETAIL', actorKey: stale.actorKey, notificationRef: ref })}`,
        );
        assert.equal(forged.status(), 404);
        assert.equal((await forged.json()).code, 'PC-AUTH-0005');
        const anonymous = await fetch(`${origin}${endpoint}?view=LIST`);
        assert.equal(anonymous.status, 404);
        assert.equal((await anonymous.json()).code, 'PC-AUTH-0005');
        const detailBeforeRestart = await current(maker, {
          view: 'DETAIL',
          actorKey: binding.actorKey,
          notificationRef: ref,
        });
        const operationBeforeRestart = await current(maker, {
          view: 'OPERATION',
          actorKey: binding.actorKey,
          operationId: acknowledged.result.operation.operationId,
        });
        await restartBrowserServices();
        await expect
          .poll(
            async () => {
              try {
                return (await maker.request.get(`${origin}${endpoint}?view=LIST`)).status();
              } catch {
                return 0;
              }
            },
            { timeout: 30000, intervals: [250, 500, 1000] },
          )
          .toBe(200);
        assert.deepEqual(
          await current(maker, {
            view: 'DETAIL',
            actorKey: binding.actorKey,
            notificationRef: ref,
          }),
          detailBeforeRestart,
        );
        assert.deepEqual(
          await current(maker, {
            view: 'OPERATION',
            actorKey: binding.actorKey,
            operationId: acknowledged.result.operation.operationId,
          }),
          operationBeforeRestart,
        );
        assert.deepEqual(await counts(), { items: 1, receipts: 2, events: 2 });
        await maker.reload();
        await maker.getByRole('combobox', { name: /^Filter field/u }).selectOption('messageKey');
        await maker.getByLabel('Filter value', { exact: true }).fill(`${messageKey}.absent`);
        await maker.getByRole('combobox', { name: /^Sort/u }).selectOption('updatedAt');
        await maker.getByRole('button', { name: 'Refresh notifications', exact: true }).click();
        await expect(maker.getByText('0 matching notifications', { exact: false })).toBeVisible();
        await expect(maker.getByRole('button', { name: 'Next page', exact: true })).toBeDisabled();
        await maker.getByRole('combobox', { name: /^Filter field/u }).selectOption('messageKey');
        await maker.getByLabel('Filter value', { exact: true }).fill(messageKey);
        await maker.getByRole('button', { name: 'Refresh notifications', exact: true }).click();
        await inspect(maker, messageKey);
        for (const width of [1440, 360]) {
          await maker.setViewportSize({ width, height: 1000 });
          assert.deepEqual(
            (
              await new AxeBuilder({ page: maker })
                .withTags(['wcag2a', 'wcag2aa', 'wcag21aa'])
                .analyze()
            ).violations,
            [],
          );
          assert.ok(await maker.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
          await maker.screenshot({
            path: join(artifacts, `notification-${width}.png`),
            fullPage: true,
          });
        }
        await maker.getByLabel('Message key', { exact: true }).focus();
        await maker.keyboard.press('Tab');
        await expect(
          maker.getByLabel('Resource reference (optional)', { exact: true }),
        ).toBeFocused();
        await maker.evaluate(() => window.dispatchEvent(new Event('blur')));
        await expect(
          maker.getByRole('heading', { name: 'Notification details', exact: true }),
        ).toHaveCount(0);
        await expect(maker.getByLabel('Message key', { exact: true })).toHaveValue('');
        await runPopulatedMetadata(maker, checker, committed, acknowledged, ref);
        await save('result.json', {
          notificationRef: ref,
          createOperation: committed.result.operation.operationId,
          acknowledgementOperation: acknowledged.result.operation.operationId,
          metadataState: 'ACKNOWLEDGED',
          populatedMetadata: 'PASS',
          deliveryAcceptance: 'OPEN',
        });
        process.stdout.write(
          `OPENPC_NOTIFICATION_BROWSER|PASS|real-oidc-webauthn|create|lost-response|exact-replay|inspect-no-ack|ack|stale-denial|context-denial|restart|signed-effects=2|keyboard|axe|reflow|populated-metadata=26|delivery=OPEN|artifacts=${artifacts}\n`,
        );
        if (process.env.OPENPC_LOCAL_RUNTIME_NOTIFICATION_ENDPOINT_BROWSER === '1')
          await runEndpointVerificationBrowser(maker, checker);
      },
    );
  } finally {
    await pool.end();
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await runNotificationBrowser();
}
