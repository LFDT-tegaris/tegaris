import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import {
  parseWorkItemBrowserArguments,
  parseNativeFleetSelection,
  parseNativeFleetMode,
  validateNativeFleetRequest,
  validateNativeFleetOperation,
  nativeFleetClaimWinner,
  retainNativeFleetProof,
  validateNativeFleetEffects,
  validateNativeFleetBinding,
  validateNativeFleetRead,
  validateNativeFleetUnchanged,
  reconcileWorkItemCapture,
  validateWorkItemActors,
  validateWorkItemRecord,
  workItemClaimWinner,
  workItemResumeAction,
  validateWorkItemReboundRead,
  keyboardFollowupIntent,
  workItemAlternateContext,
  validateNaturalWorkItemRecovery,
  workItemFollowupResume,
  assignedFollowupIntent,
  workItemAssignedResume,
  validateWorkItemPriorUi,
  workItemMutationIntent,
  validateWorkItemMutationRead,
  validateWorkItemMutationProof,
  workItemPopulationIntents,
  workItemPopulationResume,
  validateWorkItemPopulationRead,
} from './work-item-browser.mjs';

// Exercises driver input and recovery decisions only. No browser, SQL, bootstrap,
// signing or product acceptance is simulated by this corpus.
const id = (n) => `018f0019-0000-7000-8000-${String(n).padStart(12, '0')}`;
const ref = (n) => `urn:openpc:resource:${id(n)}`;
const scope = { participantId: id(1), privacyDomainId: id(2), principalRef: ref(3) };
const binding = { actorKey: `sha256:${'a'.repeat(64)}`, actor: scope };
const time = '2026-09-24T00:00:00.123456Z';
const etag = (revision) =>
  `"sha256:${createHash('sha256')
    .update(JSON.stringify({ resourceId: id(9), revision }))
    .digest('hex')}"`;
const actions = {
  CREATE: 'ACT-WORK_ITEMS_CREATE_RESOURCE-V1',
  UPDATE: 'ACT-WORK_ITEMS_UPDATE_RESOURCE-V1',
  CLAIM: 'ACT-OPERATIONS_UPDATE_CLAIM-V1',
  COMPLETE: 'ACT-OPERATIONS_UPDATE_COMPLETE-V1',
};
function record(command = 'CREATE', actor = 'maker', status = 202) {
  const revision = String(['CREATE', 'UPDATE', 'CLAIM', 'COMPLETE'].indexOf(command));
  const request = {
    actorKey: binding.actorKey,
    requestKey: id(actor === 'maker' ? 7 : 8),
    command,
    reason: 'Retained original request.',
    ...(command === 'CREATE'
      ? { kind: 'REMEDIATION', resourceRef: ref(3), assigneeRef: null }
      : {
          workItemRef: ref(9),
          expectedRevision: revision,
          etag: etag(revision),
          ...(command === 'UPDATE' ? { replacementDigest: `sha256:${'b'.repeat(64)}` } : {}),
        }),
  };
  return {
    actor,
    request,
    status,
    result:
      status === 412
        ? { code: 'PC-DATA-6007' }
        : {
            kind: 'OPERATION',
            ...binding,
            operation: {
              operationId: id(10),
              resourceRef: ref(9),
              actionIntentId: actions[command],
              intentDigest: `sha256:${'c'.repeat(64)}`,
              idempotencyKey: `workbench-work-item-${request.requestKey}`,
              state: 'SUCCEEDED',
              truthState: 'SUCCESS',
              revision: String(Number(revision) + 1),
              createdAt: time,
              updatedAt: time,
            },
          },
  };
}
function actors() {
  return Object.fromEntries(
    ['maker', 'checker'].map((name, index) => [
      name,
      {
        principalId: id(20 + index * 4),
        credentialId: id(21 + index * 4),
        envelopeId: id(22 + index * 4),
        assignmentId: id(23 + index * 4),
        privacyDomainId: scope.privacyDomainId,
        privateKeyPath: `/tmp/work-item-secrets/work-item-${name}-webauthn.pk8`,
      },
    ]),
  );
}

test('population adds only the deficit beyond page 25 and preserves exact distinct review intents', () => {
  const initial = [ref(10), ref(11), ref(12), ref(13)];
  const before = structuredClone(initial);
  const intents = workItemPopulationIntents(ref(9), initial);
  assert.equal(intents.length, 22);
  assert.equal(new Set(intents.map((intent) => intent.reason)).size, 22);
  for (const intent of intents) {
    assert.equal(intent.kind, 'REMEDIATION');
    assert.equal(intent.resourceRef, ref(9));
    assert.equal(intent.assigneeRef, null);
    assert.ok(Object.isFrozen(intent));
  }
  for (const count of [0, 1, 25, 26, 27])
    assert.equal(
      workItemPopulationIntents(
        ref(9),
        Array.from({ length: count }, (_, index) => ref(100 + index)),
      ).length,
      Math.max(0, 26 - count),
    );
  assert.deepEqual(initial, before);
  assert.deepEqual(workItemPopulationIntents(ref(9), initial), intents);
  for (const invalid of [null, new Array(1), [ref(10), ref(10)], ['invalid'], [null]])
    assert.throws(() => workItemPopulationIntents(ref(9), invalid));
  assert.throws(() => workItemPopulationIntents('invalid', initial));
});

test('population never treats unknown, denied or out-of-order captures as unused intents', () => {
  const known = record('CREATE');
  assert.equal(workItemPopulationResume([undefined, undefined]), 'FRESH_INTENTS');
  assert.equal(workItemPopulationResume([known, undefined]), 'READ_KNOWN');
  assert.equal(workItemPopulationResume([]), 'FRESH_INTENTS');
  for (const records of [
    null,
    new Array(2),
    Array.from({ length: 27 }, () => undefined),
    [undefined, known],
    [known, undefined, known],
    ...[
      null,
      {},
      { actor: known.actor, request: known.request },
      { ...known, status: 412 },
      { ...known, result: { code: 'PC-DATA-6007' } },
    ].map((value) => [value, undefined]),
  ])
    assert.throws(() => workItemPopulationResume(records));
});

test('population recovery binds the planned CREATE to original operation and authenticated scope', () => {
  const intent = workItemPopulationIntents(ref(8), [ref(10)])[0];
  const original = record('CREATE');
  Object.assign(original.request, intent);
  const before = structuredClone(original);
  const current = { ...binding, actorKey: `sha256:${'d'.repeat(64)}` };
  const observed = { ...original.result, ...current };
  assert.deepEqual(validateWorkItemPopulationRead(original, intent, current, observed), original);
  for (const invalid of [
    undefined,
    { actor: original.actor, request: original.request },
    { ...original, status: 412 },
    { ...original, actor: 'checker' },
    ...[
      { requestKey: id(99) },
      { reason: 'Replacement intent.' },
      { resourceRef: ref(99) },
      { assigneeRef: ref(99) },
      { actorKey: current.actorKey },
    ].map((patch) => ({ ...original, request: { ...original.request, ...patch } })),
  ])
    assert.throws(() => validateWorkItemPopulationRead(invalid, intent, current, observed));
  for (const patch of [{}, { ...intent, extra: true }, { ...intent, kind: 'APPROVAL' }])
    assert.throws(() => validateWorkItemPopulationRead(original, patch, current, observed));
  for (const patch of [
    { actorKey: binding.actorKey },
    { actor: { ...scope, privacyDomainId: id(99) } },
    { actor: { ...scope, principalRef: ref(99) } },
    { operation: { ...observed.operation, operationId: id(99) } },
    { operation: { ...observed.operation, resourceRef: ref(99) } },
  ])
    assert.throws(() =>
      validateWorkItemPopulationRead(original, intent, current, { ...observed, ...patch }),
    );
  assert.deepEqual(original, before);
});

test('accepts the existing five-argument runtime contract and rejects scope/command ambiguity', () => {
  const args = [
    '/tmp/work-item-secrets',
    '/tmp/work-item-evidence',
    scope.participantId,
    scope.privacyDomainId,
    JSON.stringify(['docker', 'compose', '-p', 'isolated']),
  ];
  assert.deepEqual(parseWorkItemBrowserArguments(args).compose, [
    'docker',
    'compose',
    '-p',
    'isolated',
  ]);
  for (const invalid of [
    args.slice(0, 4),
    [...args, 'extra'],
    ['relative', ...args.slice(1)],
    [...args.slice(0, 2), 'invalid', ...args.slice(3)],
    [...args.slice(0, 3), `${scope.privacyDomainId}\n`, args[4]],
    [...args.slice(0, 4), JSON.stringify(['bash', '-c', 'docker compose'])],
    [...args.slice(0, 4), JSON.stringify(['docker', 'compose', null])],
  ])
    assert.throws(() => parseWorkItemBrowserArguments(invalid));
});

test('later failed aggregates retain only exact completed UI phases, never missing or altered evidence', () => {
  const keyboard = ['CREATE', 'UPDATE', 'CLAIM', 'COMPLETE'].map((command) => record(command));
  const assigned = ['CREATE', 'CLAIM', 'COMPLETE'].map((command) => record(command));
  const result = {
    state: 'FAIL',
    gaps: [],
    originalWorkItemRef: ref(8),
    originalEffects: 4,
    followupEffects: 4,
    assignedEffects: 3,
    followupWorkItemRef: ref(9),
    assignedWorkItemRef: ref(9),
    operations: keyboard.map((value) => value.result.operation.operationId),
    assignedOperations: assigned.map((value) => value.result.operation.operationId),
  };
  const before = structuredClone(result);
  assert.equal(validateWorkItemPriorUi(result, ref(8), keyboard, assigned), 'FAIL');
  assert.deepEqual(result, before);
  for (const patch of [
    { state: 'BLOCKED' },
    { state: 'UNKNOWN' },
    { gaps: ['missing prior controls'] },
    { originalWorkItemRef: ref(7) },
    { assignedEffects: 2 },
    { followupWorkItemRef: ref(7) },
    { operations: [id(7)] },
    { assignedOperations: [] },
  ])
    assert.throws(() =>
      validateWorkItemPriorUi({ ...result, ...patch }, ref(8), keyboard, assigned),
    );
  assert.throws(() =>
    validateWorkItemPriorUi(
      result,
      ref(8),
      [keyboard[0], undefined, undefined, undefined],
      assigned,
    ),
  );
});

test('mutation invalidation uses two distinct remediation intents for the completed original resource', () => {
  const context = workItemMutationIntent(ref(8), 'context');
  const logout = workItemMutationIntent(ref(8), 'logout');
  for (const intent of [context, logout]) {
    assert.equal(intent.resourceRef, ref(8));
    assert.equal(intent.kind, 'REMEDIATION');
    assert.equal(intent.assigneeRef, null);
    assert.ok(Object.isFrozen(intent));
    assert.notEqual(intent.reason, keyboardFollowupIntent(ref(8)).reason);
  }
  assert.notEqual(context.reason, logout.reason);
  for (const transition of [null, '', 'read', 'CONTEXT'])
    assert.throws(() => workItemMutationIntent(ref(8), transition));
  assert.throws(() => workItemMutationIntent('invalid', 'logout'));
});

test('committed mutation readback rebinds real authority without rewriting the original request or effect', () => {
  for (const transition of ['context', 'logout']) {
    const original = record('CREATE', transition === 'context' ? 'maker' : 'checker');
    Object.assign(original.request, workItemMutationIntent(ref(8), transition));
    const before = structuredClone(original);
    const current = { ...binding, actorKey: `sha256:${'d'.repeat(64)}` };
    const observed = { ...original.result, ...current };
    assert.deepEqual(
      validateWorkItemMutationRead(original, transition, ref(8), current, observed),
      original,
    );
    assert.deepEqual(original, before);
    assert.equal(original.request.actorKey, binding.actorKey);
    assert.notEqual(original.request.actorKey, current.actorKey);
    for (const invalid of [
      undefined,
      { actor: original.actor, request: original.request },
      { ...original, status: 412, result: { code: 'PC-DATA-6007' } },
      { ...original, actor: original.actor === 'maker' ? 'checker' : 'maker' },
      ...[null, ref(8), 'invalid'].map((resourceRef) => ({
        ...original,
        result: { ...original.result, operation: { ...original.result.operation, resourceRef } },
      })),
      ...[
        { requestKey: id(99) },
        { actorKey: current.actorKey },
        { resourceRef: ref(99) },
        { assigneeRef: ref(99) },
        { kind: 'APPROVAL' },
        { reason: 'Replace the consumed intent.' },
      ].map((patch) => ({ ...original, request: { ...original.request, ...patch } })),
    ])
      assert.throws(() =>
        validateWorkItemMutationRead(invalid, transition, ref(8), current, observed),
      );
    for (const changed of [
      { actorKey: binding.actorKey },
      { actor: { ...scope, participantId: id(99) } },
      { actor: { ...scope, privacyDomainId: id(99) } },
      { actor: { ...scope, principalRef: ref(99) } },
      { operation: { ...observed.operation, operationId: id(99) } },
      { operation: { ...observed.operation, resourceRef: ref(99) } },
      { operation: { ...observed.operation, revision: '2' } },
    ])
      assert.throws(() =>
        validateWorkItemMutationRead(original, transition, ref(8), current, {
          ...observed,
          ...changed,
        }),
      );
    assert.deepEqual(original, before);
  }
});

test('mutation UI reuse requires exact completed proof; failed or missing proof never authorizes another CREATE', () => {
  const original = record('CREATE');
  Object.assign(original.request, workItemMutationIntent(ref(8), 'context'));
  const proof = {
    transition: 'context',
    state: 'PASS',
    effects: 1,
    uiCleared: true,
    reauthenticatedReadback: true,
    requestKey: original.request.requestKey,
    operationId: original.result.operation.operationId,
    workItemRef: original.result.operation.resourceRef,
  };
  const before = structuredClone(proof);
  assert.deepEqual(validateWorkItemMutationProof(proof, original, 'context'), proof);
  for (const patch of [
    { state: 'FAIL' },
    { state: 'BLOCKED' },
    { effects: 0 },
    { effects: 2 },
    { uiCleared: false },
    { reauthenticatedReadback: false },
    { transition: 'logout' },
    { requestKey: id(99) },
    { operationId: id(99) },
    { workItemRef: ref(99) },
  ])
    assert.throws(() => validateWorkItemMutationProof({ ...proof, ...patch }, original, 'context'));
  assert.throws(() => validateWorkItemMutationProof(undefined, original, 'context'));
  assert.throws(() =>
    validateWorkItemMutationProof(
      proof,
      { actor: original.actor, request: original.request },
      'context',
    ),
  );
  assert.throws(() => validateWorkItemMutationProof(proof, original, 'invalid'));
  assert.deepEqual(proof, before);
});

test('requires distinct work-item identities, key paths and the selected privacy domain', () => {
  const original = actors();
  assert.equal(
    validateWorkItemActors(original, '/tmp/work-item-secrets', scope.privacyDomainId),
    original,
  );
  for (const change of [
    { checker: { ...original.checker, principalId: original.maker.principalId } },
    { checker: { ...original.checker, credentialId: original.maker.credentialId } },
    { maker: { ...original.maker, privacyDomainId: id(99) } },
    {
      maker: {
        ...original.maker,
        principalId: original.maker.principalId.replace('018f0019', '018f0018'),
      },
    },
    {
      maker: {
        ...original.maker,
        privateKeyPath: '/tmp/work-item-secrets/notification-maker-webauthn.pk8',
      },
    },
    { maker: { ...original.maker, privateKeyPath: '/tmp/foreign/work-item-maker-webauthn.pk8' } },
  ])
    assert.throws(() =>
      validateWorkItemActors(
        { ...original, ...change },
        '/tmp/work-item-secrets',
        scope.privacyDomainId,
      ),
    );
  assert.throws(() =>
    validateWorkItemActors(
      { maker: original.maker },
      '/tmp/work-item-secrets',
      scope.privacyDomainId,
    ),
  );
});

test('retains exact inputs for all four transitions and reads known operations before replay', () => {
  for (const command of Object.keys(actions)) {
    const original = record(command);
    const validated = validateWorkItemRecord(
      original,
      'maker',
      binding,
      command,
      command === 'CREATE' ? undefined : ref(9),
    );
    assert.deepEqual(validated, original);
    assert.equal(workItemResumeAction(validated), 'READ_OPERATION');
    assert.equal(workItemResumeAction(validated, original.result), 'READ_ITEM');
    const lost = { actor: original.actor, request: original.request };
    assert.deepEqual(
      validateWorkItemRecord(
        lost,
        'maker',
        binding,
        command,
        command === 'CREATE' ? undefined : ref(9),
      ),
      lost,
    );
    assert.equal(workItemResumeAction(lost), 'REPLAY_EXACT');
    assert.equal(workItemResumeAction(lost, original.result), 'READ_ITEM');
    assert.deepEqual(lost.request, original.request);
  }
});

test('never rewrites a retained actor, scope, action, reference, ETag or revision', () => {
  const original = record('UPDATE');
  for (const changed of [
    { ...original, actor: 'checker' },
    { ...original, extra: true },
    { ...original, request: { ...original.request, actorKey: `sha256:${'d'.repeat(64)}` } },
    { ...original, request: { ...original.request, workItemRef: ref(99) } },
    { ...original, request: { ...original.request, etag: etag('2') } },
    { ...original, request: { ...original.request, expectedRevision: '2', etag: etag('2') } },
    { ...original, request: { ...original.request, expectedRevision: 'invalid' } },
    { ...original, request: { ...original.request, command: 'COMPLETE' } },
    { ...original, result: { ...original.result, actor: { ...scope, privacyDomainId: id(99) } } },
    { ...original, result: { ...original.result, actor: { ...scope, principalRef: ref(99) } } },
  ])
    assert.throws(() => validateWorkItemRecord(changed, 'maker', binding, 'UPDATE', ref(9)));
  for (const change of [
    { operationId: 'invalid' },
    { resourceRef: ref(99) },
    { actionIntentId: actions.CLAIM },
    { idempotencyKey: `workbench-work-item-${id(99)}` },
    { revision: '3' },
    { state: 'WRITE_AMBIGUITY' },
    { truthState: 'FAILED' },
  ])
    assert.throws(() =>
      validateWorkItemRecord(
        {
          ...original,
          result: { ...original.result, operation: { ...original.result.operation, ...change } },
        },
        'maker',
        binding,
        'UPDATE',
        ref(9),
      ),
    );
});

test('denials remain denials and uncertain or mismatched recovery is blocked', () => {
  const denied = record('CLAIM', 'checker', 412);
  assert.equal(
    workItemResumeAction(validateWorkItemRecord(denied, 'checker', binding, 'CLAIM', ref(9))),
    'RETAIN_DENIAL',
  );
  assert.throws(() =>
    validateWorkItemRecord({ ...denied, status: 503 }, 'checker', binding, 'CLAIM', ref(9)),
  );
  assert.throws(() =>
    validateWorkItemRecord(
      { ...denied, result: { code: 'PC-AUTH-0005' } },
      'checker',
      binding,
      'CLAIM',
      ref(9),
    ),
  );
  const original = record('COMPLETE');
  for (const change of [
    { state: 'RUNNING' },
    { operationId: id(99) },
    { resourceRef: ref(99) },
    { actionIntentId: actions.CLAIM },
    { idempotencyKey: `workbench-work-item-${id(99)}` },
  ])
    assert.throws(() =>
      workItemResumeAction(original, {
        ...original.result,
        operation: { ...original.result.operation, ...change },
      }),
    );
  assert.throws(() =>
    workItemResumeAction(original, { ...original.result, actorKey: `sha256:${'d'.repeat(64)}` }),
  );
  assert.throws(() =>
    workItemResumeAction(original, {
      ...original.result,
      actor: { ...scope, participantId: id(99) },
    }),
  );
  const unacknowledged = { actor: original.actor, request: original.request };
  assert.throws(() =>
    workItemResumeAction(unacknowledged, {
      ...original.result,
      operation: { ...original.result.operation, revision: '5' },
    }),
  );
});

test('the actual claim winner selects completion; partial, duplicate and inconsistent races fail closed', () => {
  for (const winner of ['maker', 'checker']) {
    const loser = winner === 'maker' ? 'checker' : 'maker';
    const won = record('CLAIM', winner),
      lost = record('CLAIM', loser, 412);
    assert.equal(workItemClaimWinner([won, lost]), winner);
    assert.equal(workItemClaimWinner([lost, won]), winner);
    assert.throws(() => workItemClaimWinner([won]));
    assert.throws(() => workItemClaimWinner([won, won]));
    assert.throws(() => workItemClaimWinner([won, { ...lost, status: 202 }]));
    assert.throws(() => workItemClaimWinner([won, { ...lost, status: undefined }]));
    assert.throws(() =>
      workItemClaimWinner([won, { ...lost, request: { ...lost.request, workItemRef: ref(99) } }]),
    );
    assert.throws(() =>
      workItemClaimWinner([won, { ...lost, request: { ...lost.request, expectedRevision: '3' } }]),
    );
  }
});

test('saving a recovery response cannot turn an unknown first outcome into a definite denial', () => {
  const accepted = record('CLAIM'),
    denied = record('CLAIM', 'maker', 412);
  const pending = { actor: accepted.actor, request: accepted.request };
  assert.deepEqual(reconcileWorkItemCapture(undefined, denied), denied);
  assert.deepEqual(reconcileWorkItemCapture(pending, accepted), accepted);
  assert.deepEqual(reconcileWorkItemCapture(accepted, accepted), accepted);
  assert.throws(() => reconcileWorkItemCapture(pending, denied));
  assert.throws(() => reconcileWorkItemCapture(accepted, denied));
  assert.throws(() => reconcileWorkItemCapture(denied, accepted));
  assert.throws(() => reconcileWorkItemCapture(pending, { ...accepted, actor: 'checker' }));
  assert.throws(() =>
    reconcileWorkItemCapture(pending, {
      ...accepted,
      request: { ...accepted.request, requestKey: id(99) },
    }),
  );
  assert.deepEqual(pending, { actor: accepted.actor, request: accepted.request });
});

test('known operations survive a new session binding without rewriting or replaying the original request', () => {
  for (const command of Object.keys(actions)) {
    const original = record(command);
    const before = structuredClone(original);
    const current = { ...binding, actorKey: `sha256:${'d'.repeat(64)}` };
    const observed = { ...original.result, ...current };
    assert.deepEqual(
      validateWorkItemReboundRead(original, 'maker', current, command, ref(9), observed),
      original,
    );
    assert.deepEqual(original, before);
    assert.equal(original.request.actorKey, binding.actorKey);
    assert.notEqual(original.request.actorKey, observed.actorKey);
  }
});

test('reauthenticated reads cannot resolve an unknown outcome or move historical authority to another actor or scope', () => {
  const original = record('COMPLETE');
  const current = { ...binding, actorKey: `sha256:${'d'.repeat(64)}` };
  const observed = { ...original.result, ...current };
  for (const value of [
    { actor: original.actor, request: original.request },
    { ...original, status: 412, result: { code: 'PC-DATA-6007' } },
    { ...original, actor: 'checker' },
    { ...original, request: { ...original.request, actorKey: current.actorKey } },
    { ...original, request: { ...original.request, requestKey: id(99) } },
  ])
    assert.throws(() =>
      validateWorkItemReboundRead(value, 'maker', current, 'COMPLETE', ref(9), observed),
    );
  for (const changed of [
    { ...current, actor: { ...scope, principalRef: ref(99) } },
    { ...current, actor: { ...scope, participantId: id(99) } },
    { ...current, actor: { ...scope, privacyDomainId: id(99) } },
  ])
    assert.throws(() =>
      validateWorkItemReboundRead(original, 'maker', changed, 'COMPLETE', ref(9), {
        ...observed,
        ...changed,
      }),
    );
  for (const changed of [
    original.result,
    { ...observed, operation: { ...observed.operation, operationId: id(99) } },
    { ...observed, operation: { ...observed.operation, revision: '5' } },
    { ...observed, operation: { ...observed.operation, resourceRef: ref(99) } },
    {
      ...observed,
      operation: { ...observed.operation, idempotencyKey: `workbench-work-item-${id(99)}` },
    },
    { ...observed, operation: { ...observed.operation, state: 'WRITE_AMBIGUITY' } },
  ])
    assert.throws(() =>
      validateWorkItemReboundRead(original, 'maker', current, 'COMPLETE', ref(9), changed),
    );
});

test('keyboard follow-up has a distinct linked intent and never changes the original business request', () => {
  const original = record();
  const before = structuredClone(original);
  const followup = keyboardFollowupIntent(original.result.operation.resourceRef);
  assert.equal(followup.kind, 'REMEDIATION');
  assert.equal(followup.resourceRef, ref(9));
  assert.notEqual(followup.resourceRef, original.request.resourceRef);
  assert.equal(followup.assigneeRef, null);
  assert.notEqual(followup.reason, original.request.reason);
  assert.ok(Object.isFrozen(followup));
  assert.deepEqual(original, before);
  for (const bad of [
    null,
    id(9),
    `${ref(9)}\n`,
    ref(9).replace('resource:', 'operation:'),
    'urn:openpc:resource:missing',
  ])
    assert.throws(() => keyboardFollowupIntent(bad));
});

test('alternate context selection requires a different advertised domain in the authenticated participant', () => {
  const here = { participantId: scope.participantId, privacyDomainId: scope.privacyDomainId };
  const alternate = { participantId: scope.participantId, privacyDomainId: id(90) };
  const session = {
    authenticated: true,
    contextMode: 'PARTICIPANT',
    ...here,
    availableContexts: [here, alternate],
  };
  assert.equal(
    workItemAlternateContext(session, scope.participantId, scope.privacyDomainId),
    alternate,
  );
  assert.equal(
    workItemAlternateContext(
      { ...session, availableContexts: [here] },
      scope.participantId,
      scope.privacyDomainId,
    ),
    undefined,
  );
  assert.equal(
    workItemAlternateContext(
      { ...session, availableContexts: [here, { ...alternate, participantId: id(91) }] },
      scope.participantId,
      scope.privacyDomainId,
    ),
    undefined,
  );
  for (const change of [
    { authenticated: false },
    { contextMode: 'PLATFORM' },
    { participantId: id(91) },
    { privacyDomainId: alternate.privacyDomainId },
    { availableContexts: undefined },
    { availableContexts: [here, here] },
    { availableContexts: [{ ...alternate, privacyDomainId: 'invalid' }] },
  ])
    assert.throws(() =>
      workItemAlternateContext(
        { ...session, ...change },
        scope.participantId,
        scope.privacyDomainId,
      ),
    );
});

test('natural uncertain recovery retains the exact request and rejects invented or already-resolved hints', () => {
  const original = record();
  const pending = { request: structuredClone(original.request), uncertain: true };
  const before = structuredClone(pending);
  assert.deepEqual(validateNaturalWorkItemRecovery(original, pending), pending);
  for (const bad of [
    null,
    { ...pending, uncertain: false },
    { ...pending, operationId: original.result.operation.operationId },
    { ...pending, request: { ...pending.request, requestKey: id(99) } },
    { ...pending, request: { ...pending.request, actorKey: `sha256:${'d'.repeat(64)}` } },
    { ...pending, request: { ...pending.request, resourceRef: ref(99) } },
    { ...pending, request: { ...pending.request, reason: 'A different business intent.' } },
  ])
    assert.throws(() => validateNaturalWorkItemRecovery(original, bad));
  assert.deepEqual(pending, before);
});

test('follow-up resumption never treats missing outcomes, malformed captures or gaps as a fresh intent', () => {
  const records = Object.keys(actions).map((command) => record(command));
  assert.equal(
    workItemFollowupResume([undefined, undefined, undefined, undefined]),
    'FRESH_INTENT',
  );
  for (let count = 1; count <= records.length; count++) {
    const prefix = records.map((value, index) => (index < count ? value : undefined));
    assert.equal(workItemFollowupResume(prefix), 'READ_KNOWN');
  }
  for (const invalid of [
    [],
    records.slice(1),
    [undefined, records[1], undefined, undefined],
    [records[0], undefined, records[2], undefined],
    ...[
      null,
      false,
      0,
      [],
      { actor: 'maker', request: records[0].request },
      { ...records[0], status: 412 },
    ].map((value) => [value, undefined, undefined, undefined]),
  ])
    assert.throws(() => workItemFollowupResume(invalid));
});

test('assignment verification has a distinct purpose, completed-item reference and concrete assignee', () => {
  const previous = keyboardFollowupIntent(ref(9));
  const assigned = assignedFollowupIntent(ref(9), ref(20));
  assert.deepEqual(assigned, {
    kind: 'REMEDIATION',
    resourceRef: ref(9),
    assigneeRef: ref(20),
    reason:
      'Verify that the assigned checker exclusively claims and completes remediation for the completed work item.',
  });
  assert.notEqual(assigned.reason, previous.reason);
  assert.equal(previous.assigneeRef, null);
  assert.ok(Object.isFrozen(assigned));
  for (const invalid of [null, '', 'invalid', ref(9), `${ref(20)}\n`])
    assert.throws(() => assignedFollowupIntent(ref(9), invalid));
  assert.throws(() => assignedFollowupIntent('invalid', ref(20)));
});

test('assignment receipts use CREATE CLAIM COMPLETE revisions without an UPDATE or rewritten request', () => {
  for (const [index, command] of ['CREATE', 'CLAIM', 'COMPLETE'].entries()) {
    const original = record(command, index === 0 ? 'maker' : 'checker');
    if (index !== 0) {
      original.request.expectedRevision = String(index);
      original.request.etag = etag(String(index));
    }
    original.result.operation.revision = String(index + 1);
    const before = structuredClone(original);
    assert.deepEqual(
      validateWorkItemRecord(original, original.actor, binding, command, ref(9), true),
      original,
    );
    const current = { ...binding, actorKey: `sha256:${'d'.repeat(64)}` };
    assert.deepEqual(
      validateWorkItemReboundRead(
        original,
        original.actor,
        current,
        command,
        ref(9),
        { ...original.result, ...current },
        true,
      ),
      original,
    );
    assert.deepEqual(original, before);
    if (index !== 0) {
      assert.throws(() =>
        validateWorkItemRecord(original, original.actor, binding, command, ref(9)),
      );
      assert.throws(() =>
        validateWorkItemRecord(record(command), 'maker', binding, command, ref(9), true),
      );
      const wrong = { ...original, actor: 'maker', status: 412, result: { code: 'PC-DATA-6007' } };
      assert.deepEqual(
        validateWorkItemRecord(wrong, 'maker', binding, command, ref(9), true),
        wrong,
      );
    }
    assert.throws(() =>
      validateWorkItemRecord(
        {
          ...original,
          result: {
            ...original.result,
            operation: { ...original.result.operation, revision: '4' },
          },
        },
        original.actor,
        binding,
        command,
        ref(9),
        true,
      ),
    );
  }
  assert.throws(() =>
    validateWorkItemRecord(record('UPDATE'), 'maker', binding, 'UPDATE', ref(9), true),
  );
});

test('assignment resumption blocks partial and unknown effects instead of issuing fresh keys', () => {
  const known = ['CREATE', 'CLAIM', 'COMPLETE'].map((command) => record(command));
  assert.equal(workItemAssignedResume([undefined, undefined, undefined]), 'FRESH_INTENT');
  assert.equal(workItemAssignedResume(known), 'READ_KNOWN');
  const before = structuredClone(known);
  for (const invalid of [
    [],
    new Array(3),
    known.slice(1),
    [...known, record('UPDATE')],
    [known[0], undefined, undefined],
    [known[0], known[1], undefined],
    [undefined, known[1], known[2]],
    ...[
      null,
      [],
      false,
      {},
      { actor: 'checker', request: known[1].request },
      { ...known[1], status: 412 },
    ].map((value) => [known[0], value, known[2]]),
  ])
    assert.throws(() => workItemAssignedResume(invalid));
  assert.deepEqual(known, before);
});

function nativeFleetFixture() {
  const selected = { eventId: id(101), candidateId: id(102), receiptId: id(103) };
  const row = {
    participantId: scope.participantId,
    privacyDomainId: scope.privacyDomainId,
    ...selected,
    workItemId: id(104),
    quarantineState: 'COMMITTED',
    kind: 'FLEET_FAILURE',
    state: 'OPEN',
    revision: '1',
    resourceRef: ref(102),
    payloadMatches: true,
    outboxMatches: true,
  };
  const native = { workItemRef: ref(104), resourceRef: ref(102) };
  const detail = {
    kind: 'DETAIL',
    ...binding,
    etag: etag(1),
    workItem: {
      workItemId: native.workItemRef,
      participantId: `urn:openpc:participant:${scope.participantId}`,
      resourceRef: native.resourceRef,
      kind: 'FLEET_FAILURE',
      state: 'OPEN',
      revision: '1',
      assigneeRef: null,
      createdAt: time,
      updatedAt: time,
    },
  };
  return { selected, row, native, detail };
}

test('native producer selection is explicit and cannot nominate a surrogate Work Item', () => {
  const { selected } = nativeFleetFixture();
  assert.equal(parseNativeFleetSelection(undefined), undefined);
  assert.deepEqual(parseNativeFleetSelection(JSON.stringify(selected)), selected);
  for (const input of [
    '',
    'null',
    '[]',
    '{}',
    JSON.stringify({ ...selected, workItemId: id(104) }),
    JSON.stringify({ ...selected, eventId: 'latest' }),
    JSON.stringify({ ...selected, receiptId: null }),
    JSON.stringify({ eventId: selected.eventId, candidateId: selected.candidateId }),
  ])
    assert.throws(() => parseNativeFleetSelection(input), /SELECTION_BLOCKED/u);
});

test('native linkage requires exactly the scoped committed producer and original OPEN Work Item', () => {
  const { selected, row, native } = nativeFleetFixture();
  assert.deepEqual(validateNativeFleetBinding([row], selected, scope), native);
  for (const rows of [[], [row, row]])
    assert.throws(() => validateNativeFleetBinding(rows, selected, scope), /CARDINALITY_BLOCKED/u);
  for (const change of [
    { participantId: id(200) },
    { privacyDomainId: id(200) },
    { eventId: id(200) },
    { candidateId: id(200) },
    { receiptId: id(200) },
    { workItemId: 'missing' },
    { quarantineState: 'PREPARED' },
    { kind: 'REMEDIATION' },
    { state: 'CLAIMED' },
    { state: 'COMPLETED' },
    { revision: '2' },
    { resourceRef: ref(200) },
    { payloadMatches: false },
    { outboxMatches: false },
  ])
    assert.throws(
      () => validateNativeFleetBinding([{ ...row, ...change }], selected, scope),
      /BINDING_BLOCKED/u,
    );
});

test('native restart readback preserves producer identity while requiring the current actor binding', () => {
  const { native, detail } = nativeFleetFixture();
  assert.deepEqual(validateNativeFleetRead(detail, binding, native), detail.workItem);
  const next = { ...binding, actorKey: `sha256:${'b'.repeat(64)}` };
  assert.deepEqual(validateNativeFleetRead({ ...detail, ...next }, next, native), detail.workItem);
  assert.throws(() => validateNativeFleetRead(detail, next, native), /PUBLIC_BINDING/u);
  assert.throws(() =>
    validateNativeFleetRead(
      { ...detail, actor: { ...scope, principalRef: ref(200) } },
      binding,
      native,
    ),
  );
  for (const change of [
    { workItemId: ref(200) },
    { resourceRef: ref(200) },
    { participantId: `urn:openpc:participant:${id(200)}` },
    { kind: 'REMEDIATION' },
    { state: 'CLAIMED' },
    { state: 'COMPLETED' },
    { revision: '2' },
    { assigneeRef: ref(3) },
    { payloadDigest: `sha256:${'c'.repeat(64)}` },
    { reason: 'private' },
  ])
    assert.throws(() =>
      validateNativeFleetRead(
        { ...detail, workItem: { ...detail.workItem, ...change } },
        binding,
        native,
      ),
    );
});

test('native inspection rejects any producer or prior Work Item effect change without leaking state', () => {
  const before = {
    receipt: Buffer.from('private-signed-bytes'),
    failureOutbox: ['original'],
    pending: ['PENDING'],
    delivery: ['QUARANTINED'],
    quarantine: ['COMMITTED'],
    inbox: [],
    cursor: ['original'],
    ack: [],
    workItems: [{ state: 'OPEN', revision: '1' }],
    priorReceipts: ['eleven-plus-mutation-and-population'],
    priorOutbox: ['original'],
  };
  validateNativeFleetUnchanged(before, { ...before });
  for (const field of Object.keys(before)) {
    assert.throws(
      () => validateNativeFleetUnchanged(before, { ...before, [field]: null }),
      (error) => error.message === 'WORK_ITEM_BROWSER_NATIVE_FLEET_FORBIDDEN_EFFECT',
    );
  }
});

test('native lifecycle requires explicit mode and original producer selection', () => {
  const { selected, row, native } = nativeFleetFixture();
  assert.equal(parseNativeFleetMode(undefined, selected), 'READ_ONLY');
  assert.equal(parseNativeFleetMode('LIFECYCLE', selected), 'LIFECYCLE');
  assert.throws(() => parseNativeFleetMode('LIFECYCLE', undefined));
  for (const value of ['', 'lifecycle', 'WRITE', ' LIFECYCLE'])
    assert.throws(() => parseNativeFleetMode(value, selected));
  for (const [state, revision] of [
    ['OPEN', '1'],
    ['CLAIMED', '2'],
    ['COMPLETED', '3'],
  ])
    assert.deepEqual(
      validateNativeFleetBinding([{ ...row, state, revision }], selected, scope, 'LIFECYCLE'),
      native,
    );
  for (const change of [
    { state: 'CLAIMED', revision: '3' },
    { state: 'CANCELLED' },
    { payloadMatches: false },
    { outboxMatches: false },
    { candidateId: id(900) },
  ])
    assert.throws(() =>
      validateNativeFleetBinding([{ ...row, ...change }], selected, scope, 'LIFECYCLE'),
    );
  assert.throws(() =>
    validateNativeFleetBinding([{ ...row, state: 'CLAIMED', revision: '2' }], selected, scope),
  );
});

function nativeRecord(command = 'CLAIM', actor = 'maker', status = 202) {
  const { native } = nativeFleetFixture();
  const value = record(command, actor, status);
  const revision = command === 'CLAIM' ? '1' : '2';
  value.binding = {
    actorKey: `sha256:${(actor === 'maker' ? 'a' : 'b').repeat(64)}`,
    actor: { ...scope, principalRef: ref(actor === 'maker' ? 3 : 4) },
  };
  value.request = {
    ...value.request,
    actorKey: value.binding.actorKey,
    workItemRef: native.workItemRef,
    expectedRevision: revision,
    etag: `"sha256:${createHash('sha256')
      .update(
        JSON.stringify({
          resourceId: native.workItemRef.slice(-36),
          revision,
        }),
      )
      .digest('hex')}"`,
  };
  if (status === 202)
    value.result = {
      ...value.result,
      ...value.binding,
      operation: {
        ...value.result.operation,
        resourceRef: native.workItemRef,
        revision: String(Number(revision) + 1),
      },
    };
  return value;
}

test('native requests use 1-to-2-to-3 without inventing CREATE, UPDATE or a new replay identity', () => {
  const { native } = nativeFleetFixture();
  for (const command of ['CLAIM', 'COMPLETE']) {
    const value = nativeRecord(command);
    assert.equal(validateNativeFleetRequest(value, native, command), value);
    for (const change of [
      { expectedRevision: '4' },
      { workItemRef: ref(900) },
      { etag: etag(1) },
      { actorKey: `sha256:${'c'.repeat(64)}` },
      { command: 'UPDATE' },
      { requestKey: id(990) },
    ])
      assert.throws(() =>
        validateNativeFleetRequest(
          { ...value, request: { ...value.request, ...change } },
          native,
          command,
        ),
      );
    for (const change of [
      { actionIntentId: actions.CREATE },
      { state: 'UNKNOWN' },
      { revision: '4' },
      { resourceRef: ref(900) },
      { idempotencyKey: 'new-request' },
    ])
      assert.throws(() =>
        validateNativeFleetRequest(
          {
            ...value,
            result: { ...value.result, operation: { ...value.result.operation, ...change } },
          },
          native,
          command,
        ),
      );
  }
  assert.throws(() => validateNativeFleetRequest(record('CREATE'), native, 'CREATE'));
});

test('native claim winner requires two distinct actor requests and retains unknown or failed race outcomes', () => {
  const { native } = nativeFleetFixture();
  const won = nativeRecord(),
    denied = nativeRecord('CLAIM', 'checker', 412);
  assert.equal(nativeFleetClaimWinner([won, denied], native), 'maker');
  for (const records of [
    [won],
    [won, won],
    [won, nativeRecord('CLAIM', 'checker')],
    [won, { actor: denied.actor, binding: denied.binding, request: denied.request }],
    [won, { ...denied, status: 409 }],
    [won, { ...denied, result: { code: 'PC-AUTH-0005' } }],
  ])
    assert.throws(() => nativeFleetClaimWinner(records, native));
});

test('native recovery binds the actual public readback without rewriting the original session or request', () => {
  const { native } = nativeFleetFixture();
  const original = nativeRecord('COMPLETE');
  const pending = { actor: original.actor, binding: original.binding, request: original.request };
  const prior = structuredClone(pending);
  const current = { ...original.binding, actorKey: `sha256:${'d'.repeat(64)}` };
  const observed = { ...original.result, ...current };
  const recovered = validateNativeFleetOperation(pending, native, current, observed);
  assert.deepEqual(pending, prior);
  assert.deepEqual(recovered.request, prior.request);
  assert.deepEqual(recovered.binding, prior.binding);
  assert.deepEqual(recovered.result, observed);
  assert.deepEqual(recovered.readbackBinding, current);
  validateNativeFleetOperation(recovered, native, current, observed);
  for (const changed of [
    { ...observed, actorKey: original.binding.actorKey },
    { ...observed, actor: { ...scope, principalRef: ref(900) } },
    { ...observed, operation: { ...observed.operation, operationId: id(900) } },
    { ...observed, operation: { ...observed.operation, idempotencyKey: 'replacement' } },
    { ...observed, operation: { ...observed.operation, revision: '4' } },
  ])
    assert.throws(() => validateNativeFleetOperation(original, native, current, changed));
  assert.throws(() =>
    validateNativeFleetOperation(nativeRecord('COMPLETE', 'maker', 412), native, current, observed),
  );
});

function nativeSnapshots() {
  const { native } = nativeFleetFixture();
  const item = {
    work_item_id: id(104),
    kind: 'FLEET_FAILURE',
    state: 'OPEN',
    row_version: 1,
    resource_ref: native.resourceRef,
    payload_digest: 'original-material',
    reason: 'original',
    created_by_principal_id: id(500),
    assignee_principal_id: null,
    claimed_by_principal_id: null,
    completed_by_principal_id: null,
    created_at: time,
    updated_at: time,
  };
  const before = {
    'control.work_item': [
      { retained: item },
      { retained: { work_item_id: id(800), state: 'OPEN' } },
    ],
    'control.audit_occurrence': [],
    'control.outbox_event': [],
    'control.fleet_fact_quarantine': [{ state: 'COMMITTED', signedBytes: 'original' }],
    'control.fleet_fact_failure_outbox': [{ original: true }],
    'control.fleet_fact_delivery': [{ state: 'QUARANTINED' }],
    'control.fleet_fact_admission_cursor': [],
    'control.fleet_fact_admission_inbox': [],
    'facts.canonical_fact': [{ unchanged: true }],
    'facts.outbox': [{ state: 'PENDING' }],
    'facts.fleet_admission_ack': [],
    'facts.control_admission_custody_ack': [],
  };
  const transitions = [
    { command: 'CLAIM', principalId: id(3), operationId: id(31) },
    { command: 'COMPLETE', principalId: id(3), operationId: id(32) },
  ];
  const after = structuredClone(before);
  after['control.work_item'][0].retained = {
    ...item,
    state: 'COMPLETED',
    row_version: 3,
    assignee_principal_id: id(3),
    claimed_by_principal_id: id(3),
    completed_by_principal_id: id(3),
    updated_at: 'later',
  };
  for (const table of ['control.audit_occurrence', 'control.outbox_event'])
    after[table] = transitions.map((transition) => ({
      retained: { aggregate_id: id(104), operation: transition.operationId },
    }));
  return { native, before, after, transitions };
}

test('native restart cannot replace original signed receipt or outbox bytes with a newly valid proof', () => {
  const proof = {
    receiptId: id(701),
    payload: 'cGF5bG9hZA==',
    cose: 'cHJvb2Y=',
    before: 'YmVmb3Jl',
    after: 'YWZ0ZXI=',
    eventId: id(702),
    eventPayload: 'ZXZlbnQ=',
    sequence: '1',
  };
  assert.equal(retainNativeFleetProof(undefined, proof), proof);
  assert.equal(retainNativeFleetProof(proof, { ...proof }), proof);
  for (const key of Object.keys(proof))
    assert.throws(
      () => retainNativeFleetProof(proof, { ...proof, [key]: 'replacement-private-canary' }),
      (error) => error.message === 'WORK_ITEM_BROWSER_NATIVE_FLEET_ORIGINAL_SIGNED_BYTES',
    );
});

test('native effect boundary permits only exact claimant lifecycle and two separately verified receipt/outbox effects', () => {
  const { native, before, after, transitions } = nativeSnapshots();
  validateNativeFleetEffects(before, before, native, []);
  validateNativeFleetEffects(before, after, native, transitions);
  for (const table of Object.keys(before).filter(
    (key) =>
      !['control.work_item', 'control.audit_occurrence', 'control.outbox_event'].includes(key),
  )) {
    assert.throws(
      () =>
        validateNativeFleetEffects(before, { ...after, [table]: ['changed'] }, native, transitions),
      (error) => error.message === 'WORK_ITEM_BROWSER_NATIVE_FLEET_FORBIDDEN_EFFECT',
    );
  }
  for (const change of [
    { completed_by_principal_id: id(4) },
    { claimed_by_principal_id: id(4) },
    { payload_digest: 'replacement' },
    { reason: 'edited' },
    { created_by_principal_id: id(3) },
    { resource_ref: ref(900) },
    { row_version: 4 },
  ]) {
    const invalid = structuredClone(after);
    Object.assign(invalid['control.work_item'][0].retained, change);
    assert.throws(() => validateNativeFleetEffects(before, invalid, native, transitions));
  }
  const unrelated = structuredClone(after);
  unrelated['control.work_item'][1].retained.state = 'COMPLETED';
  assert.throws(() => validateNativeFleetEffects(before, unrelated, native, transitions));
  for (const table of ['control.audit_occurrence', 'control.outbox_event']) {
    const extra = structuredClone(after);
    extra[table].push({ retained: { aggregate_id: id(104) } });
    assert.throws(() => validateNativeFleetEffects(before, extra, native, transitions));
  }
  assert.throws(() => validateNativeFleetEffects({}, {}, native, []));
  assert.throws(() =>
    validateNativeFleetEffects(before, after, native, [
      transitions[0],
      { ...transitions[1], principalId: id(4) },
    ]),
  );
});
