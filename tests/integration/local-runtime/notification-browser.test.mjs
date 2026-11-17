import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  assertEndpointDenial,
  assertEndpointReplay,
  endpointAlternateContext,
  requireEndpointMutationContext,
  requireRetainedEndpointContext,
  restoreEndpointBrowserContext,
  assertEndpointFirstCommit,
  endpointEffectQueries,
} from './notification-browser.mjs';

const effects = () => ({
  endpoints: [{ endpoint_id: 'original', state: 'DISABLED', revision: '1' }],
  receipts: [{ operation_id: 'operation', receipt_cbor: Buffer.from('original signed bytes') }],
  events: [{ event_id: 'event', payload_cbor: Buffer.from('original event') }],
});
const denied = () => ({
  status: 404,
  expectedStatus: 404,
  code: 'PC-AUTH-0005',
  problem: { status: 404, code: 'PC-AUTH-0005', truthState: 'DENIED' },
  before: effects(),
  after: effects(),
});
test('denial requires the expected owner result and zero durable effects', () => {
  assert.doesNotThrow(() => assertEndpointDenial(denied()));
  assert.doesNotThrow(() =>
    assertEndpointDenial({
      ...denied(),
      status: 412,
      expectedStatus: 412,
      code: 'PC-DATA-6007',
      problem: { status: 412, code: 'PC-DATA-6007', truthState: 'STALE' },
    }),
  );
  for (const change of [
    { status: 202 },
    { status: 503 },
    { problem: { status: 404, code: 'PC-INTEGRATION-5001' } },
    { problem: { ...denied().problem, operation: {} } },
    { problem: { ...denied().problem, credential: 'private' } },
    { problem: { ...denied().problem, truthState: 'UNKNOWN' } },
    { after: { ...effects(), endpoints: [...effects().endpoints, { endpoint_id: 'extra' }] } },
    { after: { ...effects(), receipts: [...effects().receipts, effects().receipts[0]] } },
    { after: { ...effects(), events: [] } },
  ])
    assert.throws(() => assertEndpointDenial({ ...denied(), ...change }));
});
for (const command of ['CREATE', 'UPDATE']) {
  const request = {
    command,
    requestKey: 'original-key',
    actorKey: 'original-actor',
    candidateDigest: 'digest',
    ...(command === 'CREATE'
      ? { destinationRef: 'installed-destination' }
      : {
          endpointRef: 'original-endpoint',
          expectedRevision: '2',
          etag: 'original-etag',
          replacementDigest: 'original-binding',
        }),
  };
  const result = {
    operation: {
      operationId: 'original-operation',
      state: 'SUCCEEDED',
      revision: command === 'CREATE' ? '1' : '3',
    },
  };
  const replay = () => ({
    request: structuredClone(request),
    status: 202,
    result: structuredClone(result),
    original: { request, result },
    before: effects(),
    after: effects(),
  });
  test(`${command} recovery rejects substituted requests, operations and duplicate effects`, () => {
    assert.doesNotThrow(() => assertEndpointReplay(replay()));
    for (const key of Object.keys(request)) {
      assert.throws(() =>
        assertEndpointReplay({ ...replay(), request: { ...request, [key]: 'changed' } }),
      );
    }
    assert.throws(() => assertEndpointReplay({ ...replay(), status: 409 }));
    assert.throws(() =>
      assertEndpointReplay({
        ...replay(),
        result: { operation: { ...result.operation, operationId: 'another' } },
      }),
    );
    assert.throws(() =>
      assertEndpointReplay({
        ...replay(),
        after: {
          ...effects(),
          receipts: [{ ...effects().receipts[0], receipt_cbor: Buffer.from('changed bytes') }],
        },
      }),
    );
    assert.throws(() =>
      assertEndpointReplay({
        ...replay(),
        after: { ...effects(), events: [...effects().events, effects().events[0]] },
      }),
    );
  });
}

const id = (n) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
test('only an actual distinct advertised context can admit first-mutation context acceptance', () => {
  const session = {
    authenticated: true,
    contextMode: 'PARTICIPANT',
    sessionId: id(1),
    principalId: id(2),
    participantId: id(3),
    privacyDomainId: id(4),
    availableContexts: [{ participantId: id(3), privacyDomainId: id(4) }],
  };
  assert.equal(endpointAlternateContext(session, id(3), id(4)), undefined);
  const alternate = { participantId: id(3), privacyDomainId: id(5) };
  assert.deepEqual(
    endpointAlternateContext(
      { ...session, availableContexts: [...session.availableContexts, alternate] },
      id(3),
      id(4),
    ),
    alternate,
  );
  assert.equal(
    endpointAlternateContext(
      { ...session, availableContexts: [{ ...alternate, participantId: id(9) }] },
      id(3),
      id(4),
    ),
    undefined,
  );
  for (const changed of [
    { authenticated: false },
    { privacyDomainId: id(9) },
    { availableContexts: [alternate, alternate] },
    { availableContexts: [{ participantId: id(3), privacyDomainId: 'invented' }] },
  ])
    assert.throws(() => endpointAlternateContext({ ...session, ...changed }, id(3), id(4)));
});
for (const command of ['CREATE', 'UPDATE'])
  test(`${command} first commit requires one original operation, receipt and event with no verification send`, () => {
    const record = {
      status: 202,
      request: { command },
      result: {
        operation: {
          operationId: id(7),
          state: 'SUCCEEDED',
          truthState: 'SUCCESS',
          resourceRef: `urn:openpc:resource:${id(8)}`,
          revision: command === 'CREATE' ? '1' : '2',
        },
      },
    };
    const before = {
      endpoints:
        command === 'CREATE' ? [] : [{ endpoint_id: id(8), revision: '1', state: 'ACTIVE' }],
      operations: [],
      receipts: [],
      events: [],
      attempts: [],
    };
    const after = {
      endpoints: [
        { endpoint_id: id(8), revision: record.result.operation.revision, state: 'DISABLED' },
      ],
      operations: [{ operation_id: id(7) }],
      receipts: [{ operation_id: id(7), receipt_cbor: Buffer.from('signed') }],
      events: [{ correlation_id: id(7) }],
      attempts: [],
    };
    assert.doesNotThrow(() => assertEndpointFirstCommit(before, after, record));
    for (const key of ['operations', 'receipts', 'events']) {
      assert.throws(() => assertEndpointFirstCommit(before, { ...after, [key]: [] }, record));
      assert.throws(() =>
        assertEndpointFirstCommit(
          before,
          { ...after, [key]: [...after[key], ...after[key]] },
          record,
        ),
      );
    }
    assert.throws(() =>
      assertEndpointFirstCommit(
        before,
        { ...after, attempts: [{ attempt_id: 'extra-send' }] },
        record,
      ),
    );
    assert.throws(() =>
      assertEndpointFirstCommit(
        before,
        { ...after, endpoints: [{ ...after.endpoints[0], revision: '9' }] },
        record,
      ),
    );
  });
test('exact endpoint snapshot SQL references columns in the committed owning Drizzle schemas', async () => {
  const { getTableColumns } = await import('drizzle-orm');
  const { notificationEndpoints } =
    await import('../../../services/control-api/src/notifications/schema.ts');
  const { notificationVerificationAttempts } =
    await import('../../../services/control-api/src/notifications/endpoint-admission-schema.ts');
  const { idempotencyRecords, outboxEvents } =
    await import('../../../services/identity-service/src/db/schema/workflow.ts');
  const { auditOccurrences } =
    await import('../../../services/identity-service/src/db/schema/business-receipts.ts');
  const tables = {
    notification_endpoint: notificationEndpoints,
    notification_verification_attempt: notificationVerificationAttempts,
    idempotency_record: idempotencyRecords,
    audit_occurrence: auditOccurrences,
    outbox_event: outboxEvents,
  };
  for (const query of Object.values(endpointEffectQueries)) {
    const match = /^select (.+) from control\.(\w+) where (.+) order by (\w+)$/u.exec(query);
    assert.ok(match, 'Read-only known scoped snapshot shape required');
    const columns = new Set(
      Object.values(getTableColumns(tables[match[2]])).map((column) => column.name),
    );
    const selected = match[1] === '*' ? [] : match[1].split(',');
    const filtered = [...match[3].matchAll(/(\w+)=/gu)].map((entry) => entry[1]);
    for (const column of [...selected, ...filtered, match[4]])
      assert.ok(columns.has(column), `Unknown ${match[2]}.${column}`);
    assert.match(match[3], /participant_id=\$1 and privacy_domain_id=\$2/u);
  }
});

test('required first-context preflight blocks before the selected mutation; explicit replay mode stays separate', () => {
  const session = {
    authenticated: true,
    contextMode: 'PARTICIPANT',
    sessionId: id(1),
    principalId: id(2),
    participantId: id(3),
    privacyDomainId: id(4),
    availableContexts: [{ participantId: id(3), privacyDomainId: id(4) }],
  };
  let effects = 0;
  const selectedMutation = (mode) => {
    requireEndpointMutationContext(session, id(3), id(4), mode);
    effects++;
  };
  assert.throws(() => selectedMutation(undefined), /BLOCKED_NOTIFICATION_ENDPOINT_FIRST_CONTEXT/u);
  assert.throws(
    () => selectedMutation('first-mutation-context'),
    /BLOCKED_NOTIFICATION_ENDPOINT_FIRST_CONTEXT/u,
  );
  assert.equal(effects, 0);
  assert.equal(requireEndpointMutationContext(undefined, id(3), id(4), 'replay-logout'), undefined);
  assert.throws(() => selectedMutation('implicit-fallback'), /Unknown/u);
  assert.equal(effects, 0);
  const alternate = { participantId: id(3), privacyDomainId: id(5) };
  assert.deepEqual(
    requireEndpointMutationContext(
      { ...session, availableContexts: [...session.availableContexts, alternate] },
      id(3),
      id(4),
    ),
    alternate,
  );
});
function contextReturnFixture(change = {}) {
  const origin = 'http://localhost:8080';
  const originalSession = { principalId: id(2), sessionId: id(1) };
  const availableContexts = [
    { participantId: id(3), privacyDomainId: id(4) },
    { participantId: id(3), privacyDomainId: id(5) },
  ];
  const current = {
    authenticated: true,
    contextMode: 'PARTICIPANT',
    participantId: id(3),
    privacyDomainId: id(5),
    principalId: id(2),
    sessionId: id(6),
    availableContexts,
    ...change.current,
  };
  const returned = {
    participantId: id(3),
    privacyDomainId: id(4),
    contextMode: 'PARTICIPANT',
    sessionId: id(7),
    ...change.returned,
  };
  const restored = { ...current, ...returned, ...change.restored };
  const calls = [];
  let reads = 0,
    predicate,
    capture;
  const replied = Promise.withResolvers(),
    loaded = Promise.withResolvers();
  const response = {
    status: () => change.status ?? 201,
    request: () => ({
      method: () => 'POST',
      postDataJSON: () => ({
        participantId: id(3),
        privacyDomainId: id(4),
        expectedSessionId: id(6),
      }),
    }),
    url: () => `${origin}/api/v1/ui/session/context`,
    json: async () => returned,
  };
  const page = {
    route: async (_pattern, handler) => {
      capture = handler;
    },
    unroute: async () => {
      capture = undefined;
    },
    request: {
      get: async (url) => {
        calls.push(['GET', url]);
        return { status: () => 200, json: async () => (reads++ === 0 ? current : restored) };
      },
    },
    waitForResponse: (filter) => {
      predicate = filter;
      return replied.promise;
    },
    waitForEvent: (name) => {
      assert.equal(name, 'load');
      return loaded.promise;
    },
    getByRole: (role, options) => {
      if (role === 'combobox') {
        assert.equal(options.name, 'Organization workspace');
        return { selectOption: async (value) => calls.push(['SELECT', value]) };
      }
      assert.equal(role, 'button');
      assert.equal(options.name, 'Verify and enter workspace');
      return {
        click: async () => {
          calls.push(['CONTEXT_WITH_STEP_UP']);
          assert.equal(predicate(response), true);
          await capture({
            request: response.request,
            fetch: async () => response,
            fulfill: async () => {
              replied.resolve({
                ...response,
                json: async () => {
                  throw new Error('body evicted after reload');
                },
              });
              loaded.resolve();
            },
          });
        },
      };
    },
  };
  return {
    args: { page, origin, participantId: id(3), privacyDomainId: id(4), originalSession },
    calls,
  };
}
test('authenticated return uses only advertised selector/step-up and current-session readback, never a new login or endpoint mutation', async () => {
  const { args, calls } = contextReturnFixture();
  const restored = await restoreEndpointBrowserContext(args);
  assert.equal(restored.privacyDomainId, id(4));
  assert.equal(restored.principalId, id(2));
  assert.deepEqual(calls, [
    ['GET', 'http://localhost:8080/api/v1/ui/local-session'],
    ['SELECT', id(4)],
    ['CONTEXT_WITH_STEP_UP'],
    ['GET', 'http://localhost:8080/api/v1/ui/local-session'],
  ]);
});
test('context return fails closed on missing original advertisement, wrong actor, owner denial or mismatched readback', async () => {
  for (const change of [
    { current: { availableContexts: [{ participantId: id(3), privacyDomainId: id(5) }] } },
    { current: { principalId: id(99) } },
    { current: { authenticated: false } },
    { status: 404 },
    { returned: { sessionId: id(6) } },
    { restored: { sessionId: id(8) } },
    { restored: { principalId: id(99) } },
    { restored: { privacyDomainId: id(5) } },
  ]) {
    const { args } = contextReturnFixture(change);
    await assert.rejects(restoreEndpointBrowserContext(args));
  }
});

test('retained readback preserves an unresolved first-context predicate instead of treating it as passed or recreating its effect', () => {
  for (const proof of [
    undefined,
    { operationId: id(7), state: 'FAIL' },
    { operationId: id(7), state: 'PASS', firstMutation: false, mountedBeforeAndAfter: true },
  ])
    assert.throws(
      () => requireRetainedEndpointContext(proof, id(7)),
      /BLOCKED_NOTIFICATION_ENDPOINT_FIRST_CONTEXT/u,
    );
  assert.doesNotThrow(() => requireRetainedEndpointContext(undefined, id(7), 'replay-logout'));
  const passed = {
    operationId: id(7),
    state: 'PASS',
    firstMutation: true,
    mountedBeforeAndAfter: true,
  };
  assert.doesNotThrow(() => requireRetainedEndpointContext(passed, id(7)));
  assert.throws(() => requireRetainedEndpointContext(passed, id(8)), /another original/u);
});

test('notification initial actor preflight separates business scope from alternate entry authority', async () => {
  const { execFileSync } = await import('node:child_process');
  const run = (privacy = '018f0000-0000-7000-8000-000000000201') =>
    JSON.parse(
      execFileSync(
        process.execPath,
        [
          '--import',
          'tsx',
          'tests/integration/local-runtime/deployment-intent-actors.mjs',
          '/unused/secrets',
          '/unused/evidence',
          '018f0000-0000-7000-8000-000000000101',
          'bootstrap-notifications',
          privacy,
          '018f0018-0000-7000-8000-000000000201',
          '--preflight',
        ],
        { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
      ),
    );
  const value = run();
  assert.deepEqual(value.privacyDomainIds, ['018f0000-0000-7000-8000-000000000201']);
  assert.deepEqual(value.entryPrivacyDomains, ['018f0018-0000-7000-8000-000000000201']);
  assert.deepEqual(value.entryActions, [
    'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
    'ACT-IDENTITY_CREATE_SESSION-V1',
    'ACT-IDENTITY_UPDATE_STEP_UP-V1',
  ]);
  for (const [name, actor] of Object.entries(value.actors)) {
    assert.match(actor.principalId, /^018f0018-/u);
    assert.notEqual(value.entryAuthorities[name].assignmentId, actor.assignmentId);
    assert.notEqual(value.entryAuthorities[name].envelopeId, actor.envelopeId);
  }
  assert.throws(() => run('018f0019-0000-7000-8000-000000000201'));
});
