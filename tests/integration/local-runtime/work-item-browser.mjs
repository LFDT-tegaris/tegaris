import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { basename, isAbsolute, join, resolve, sep } from 'node:path';
import { pathToFileURL } from 'node:url';
import { isDeepStrictEqual, promisify } from 'node:util';
import {
  workItemActions,
  workItemBinding,
  workItemCommand,
  workItemId,
  workItemPending,
  workItemView,
} from '../../../apps/admin-web/lib/work-item-workflow.ts';

const endpoint = '/api/v1/ui/work-item-workbench';
const origin = 'http://localhost:8080';
const storageKey = 'openpc:work-item-request:v1';
const commands = ['CREATE', 'UPDATE', 'CLAIM', 'COMPLETE'];
const assignedCommands = ['CREATE', 'CLAIM', 'COMPLETE'];
const actorNames = ['maker', 'checker'];
const ref = (id) => `urn:openpc:resource:${id}`;
const hash = (bytes) => createHash('sha256').update(bytes).digest();
const requireThat = (condition, boundary) => {
  if (!condition) throw new Error(`WORK_ITEM_BROWSER_${boundary}`);
};

/** Also used by the companion tests. Importing this driver never launches a browser. */
export function parseWorkItemBrowserArguments(args) {
  requireThat(args.length === 5, 'ARGUMENTS');
  const [secretRoot, evidenceRoot, participantId, privacyDomainId, encodedCompose] = args;
  requireThat(isAbsolute(secretRoot) && isAbsolute(evidenceRoot), 'ARTIFACT_ROOT');
  requireThat(
    workItemId.safeParse(participantId).success && workItemId.safeParse(privacyDomainId).success,
    'SCOPE',
  );
  const compose = JSON.parse(encodedCompose);
  requireThat(
    Array.isArray(compose) &&
      compose.length >= 2 &&
      compose[0] === 'docker' &&
      compose[1] === 'compose' &&
      compose.every((v) => typeof v === 'string' && v.length > 0 && !v.includes('\0')),
    'COMPOSE',
  );
  return { secretRoot, evidenceRoot, participantId, privacyDomainId, compose };
}

/** Existing actor-file shape, but separately bootstrapped identities and key files.
 * These checks establish fixture identity only; actual owner authorization follows. */
export function validateWorkItemActors(actors, secretRoot, privacyDomainId) {
  requireThat(
    actors && typeof actors === 'object' && actorNames.every((name) => actors[name]),
    'ACTORS_REQUIRED',
  );
  const ids = new Set(),
    keys = new Set();
  for (const name of actorNames) {
    const actor = actors[name];
    for (const field of ['principalId', 'credentialId', 'envelopeId', 'assignmentId']) {
      requireThat(
        workItemId.safeParse(actor[field]).success && !ids.has(actor[field]),
        'ACTOR_ISOLATION',
      );
      ids.add(actor[field]);
    }
    requireThat(actor.privacyDomainId === privacyDomainId, 'ACTOR_SCOPE');
    requireThat(
      typeof actor.privateKeyPath === 'string' &&
        resolve(actor.privateKeyPath).startsWith(`${resolve(secretRoot)}${sep}`) &&
        basename(actor.privateKeyPath) === `work-item-${name}-webauthn.pk8` &&
        !keys.has(actor.privateKeyPath),
      'WORK_ITEM_KEYS_REQUIRED',
    );
    requireThat(!actor.principalId.startsWith('018f0018-'), 'NOTIFICATION_ACTOR_FORBIDDEN');
    keys.add(actor.privateKeyPath);
  }
  return actors;
}

/** A retained request is never rewritten to match a new session or business state. */
export function validateWorkItemRecord(
  value,
  actor,
  binding,
  command,
  workItemRef,
  assigned = false,
) {
  requireThat(value && typeof value === 'object' && value.actor === actor, 'RETAINED_ACTOR');
  const parsed = workItemCommand.safeParse(value.request);
  requireThat(parsed.success, 'RETAINED_REQUEST');
  const request = parsed.data;
  requireThat(
    Object.keys(value).every((key) => ['actor', 'request', 'status', 'result'].includes(key)),
    'RETAINED_FIELDS',
  );
  const sequence = assigned ? assignedCommands : commands;
  requireThat(sequence.includes(command), 'RETAINED_COMMAND');
  if (command !== 'CREATE') {
    requireThat(
      request.expectedRevision === String(sequence.indexOf(command)),
      'RETAINED_TRANSITION_REVISION',
    );
    const expected = `"sha256:${hash(Buffer.from(JSON.stringify({ resourceId: request.workItemRef.slice(-36), revision: request.expectedRevision }))).toString('hex')}"`;
    requireThat(request.etag === expected, 'RETAINED_ETAG');
  }
  requireThat(
    request.actorKey === binding.actorKey && request.command === command,
    'RETAINED_BINDING',
  );
  if (command !== 'CREATE') requireThat(request.workItemRef === workItemRef, 'RETAINED_RESOURCE');
  if (value.status === undefined) {
    requireThat(value.result === undefined, 'RETAINED_OUTCOME');
    return { ...value, request };
  }
  requireThat(value.status === 202 || value.status === 412, 'RETAINED_STATUS');
  if (value.status === 412) {
    requireThat(value.result?.code === 'PC-DATA-6007', 'RETAINED_DENIAL');
    return { ...value, request };
  }
  const result = workItemView.safeParse(value.result);
  requireThat(result.success && result.data.kind === 'OPERATION', 'RETAINED_OPERATION');
  const operation = result.data.operation;
  requireThat(
    result.data.actorKey === binding.actorKey &&
      result.data.actor.participantId === binding.actor.participantId &&
      result.data.actor.privacyDomainId === binding.actor.privacyDomainId &&
      result.data.actor.principalRef === binding.actor.principalRef,
    'RETAINED_SCOPE',
  );
  requireThat(
    operation.actionIntentId === workItemActions[command] &&
      operation.idempotencyKey === `workbench-work-item-${request.requestKey}` &&
      operation.state === 'SUCCEEDED' &&
      operation.truthState === 'SUCCESS',
    'RETAINED_OPERATION_BINDING',
  );
  requireThat(
    operation.revision ===
      (command === 'CREATE' ? '1' : String(BigInt(request.expectedRevision) + 1n)),
    'RETAINED_REVISION',
  );
  if (workItemRef) requireThat(operation.resourceRef === workItemRef, 'RETAINED_RESOURCE');
  return { ...value, request, result: result.data };
}

/** READ comes before replay. Missing acknowledgements never authorize a new key. */
export function workItemResumeAction(record, observedOperation) {
  if (record.status === 412) return 'RETAIN_DENIAL';
  if (observedOperation !== undefined) {
    const parsed = workItemView.safeParse(observedOperation);
    requireThat(parsed.success && parsed.data.kind === 'OPERATION', 'RECOVERY_READ');
    const actual = parsed.data.operation;
    requireThat(parsed.data.actorKey === record.request.actorKey, 'RECOVERY_ACTOR');
    if (record.result)
      assert.deepEqual(parsed.data.actor, record.result.actor, 'WORK_ITEM_BROWSER_RECOVERY_SCOPE');
    requireThat(
      actual.actionIntentId === workItemActions[record.request.command] &&
        actual.idempotencyKey === `workbench-work-item-${record.request.requestKey}`,
      'RECOVERY_IDENTITY',
    );
    requireThat(
      actual.revision ===
        (record.request.command === 'CREATE'
          ? '1'
          : String(BigInt(record.request.expectedRevision) + 1n)),
      'RECOVERY_REVISION',
    );
    if (record.request.command !== 'CREATE')
      requireThat(actual.resourceRef === record.request.workItemRef, 'RECOVERY_RESOURCE');
    if (record.result)
      assert.deepEqual(
        actual,
        record.result.operation,
        'WORK_ITEM_BROWSER_RECOVERY_ORIGINAL_BYTES',
      );
    requireThat(
      actual.state === 'SUCCEEDED' && actual.truthState === 'SUCCESS',
      'RECOVERY_UNRESOLVED',
    );
    return 'READ_ITEM';
  }
  return record.result ? 'READ_OPERATION' : 'REPLAY_EXACT';
}

/** A later denial cannot resolve an earlier request whose outcome was never saved. */
export function reconcileWorkItemCapture(prior, observed) {
  if (prior) {
    assert.deepEqual(prior.request, observed.request, 'WORK_ITEM_BROWSER_RECOVERY_REQUEST');
    requireThat(prior.actor === observed.actor, 'RECOVERY_ACTOR');
    if (prior.status === undefined) requireThat(observed.status === 202, 'RECOVERY_UNRESOLVED');
    else assert.deepEqual(observed, prior, 'WORK_ITEM_BROWSER_RECOVERY_ORIGINAL_BYTES');
  }
  return observed;
}

export function workItemClaimWinner(records) {
  requireThat(
    records.length === 2 &&
      new Set(records.map((r) => r.actor)).size === 2 &&
      records.every((r) => actorNames.includes(r.actor) && r.request.command === 'CLAIM'),
    'CLAIM_ACTORS',
  );
  requireThat(
    records[0].request.workItemRef === records[1].request.workItemRef &&
      records.every((r) => r.request.expectedRevision === '2') &&
      records[0].request.requestKey !== records[1].request.requestKey,
    'CLAIM_INTENT',
  );
  requireThat(
    records
      .map((r) => r.status)
      .sort()
      .join(',') === '202,412',
    'CLAIM_CARDINALITY',
  );
  return records.find((r) => r.status === 202).actor;
}

/** Read a known historical operation under a newly authenticated session. This
 * never rewrites the old request or permits resubmission with a replacement key. */
export function validateWorkItemReboundRead(
  record,
  actor,
  binding,
  command,
  itemRef,
  observed,
  assigned = false,
) {
  requireThat(
    record?.status === 202 && record.result?.kind === 'OPERATION',
    'KNOWN_OPERATION_REQUIRED',
  );
  const original = validateWorkItemRecord(record, actor, record.result, command, itemRef, assigned);
  assert.deepEqual(binding.actor, original.result.actor, 'WORK_ITEM_BROWSER_RECOVERY_SCOPE');
  const current = workItemView.parse(observed);
  requireThat(
    current.kind === 'OPERATION' && current.actorKey === binding.actorKey,
    'RECOVERY_BINDING',
  );
  assert.deepEqual(current.actor, binding.actor, 'WORK_ITEM_BROWSER_RECOVERY_SCOPE');
  assert.deepEqual(
    current.operation,
    original.result.operation,
    'WORK_ITEM_BROWSER_RECOVERY_ORIGINAL_BYTES',
  );
  return original;
}

export function keyboardFollowupIntent(originalRef) {
  requireThat(
    typeof originalRef === 'string' &&
      originalRef.startsWith('urn:openpc:resource:') &&
      workItemId.safeParse(originalRef.slice('urn:openpc:resource:'.length)).success,
    'FOLLOWUP_RESOURCE',
  );
  return Object.freeze({
    kind: 'REMEDIATION',
    resourceRef: originalRef,
    assigneeRef: null,
    reason:
      'Verify keyboard handling and recovery for a remediation follow-up to the completed work item.',
  });
}

/** A distinct business intent; the assignee is an existing authenticated checker. */
export function assignedFollowupIntent(originalRef, checkerRef) {
  keyboardFollowupIntent(originalRef);
  requireThat(
    typeof checkerRef === 'string' &&
      checkerRef.startsWith('urn:openpc:resource:') &&
      workItemId.safeParse(checkerRef.slice('urn:openpc:resource:'.length)).success &&
      checkerRef !== originalRef,
    'ASSIGNED_PRINCIPAL',
  );
  return Object.freeze({
    kind: 'REMEDIATION',
    resourceRef: originalRef,
    assigneeRef: checkerRef,
    reason:
      'Verify that the assigned checker exclusively claims and completes remediation for the completed work item.',
  });
}

export function workItemMutationIntent(originalRef, transition) {
  keyboardFollowupIntent(originalRef);
  requireThat(['context', 'logout'].includes(transition), 'MUTATION_TRANSITION');
  return Object.freeze({
    kind: 'REMEDIATION',
    resourceRef: originalRef,
    assigneeRef: null,
    reason:
      transition === 'context'
        ? 'Verify original remediation readback after a context change hides its delayed CREATE response.'
        : 'Verify original remediation readback after logout hides its delayed CREATE response.',
  });
}

/** A committed effect survives UI invalidation. Only its original operation is
 * read under new real authority; an unknown outcome never permits resubmission. */
export function validateWorkItemMutationRead(record, transition, originalRef, binding, observed) {
  const intent = workItemMutationIntent(originalRef, transition);
  const actor = transition === 'context' ? 'maker' : 'checker';
  requireThat(
    record?.status === 202 && record.result?.kind === 'OPERATION',
    'MUTATION_OUTCOME_BLOCKED',
  );
  for (const [key, value] of Object.entries(intent))
    assert.deepEqual(record.request?.[key], value, 'WORK_ITEM_BROWSER_MUTATION_ORIGINAL_INTENT');
  const resourceRef = record.result.operation?.resourceRef;
  requireThat(
    typeof resourceRef === 'string' &&
      resourceRef.startsWith('urn:openpc:resource:') &&
      workItemId.safeParse(resourceRef.slice('urn:openpc:resource:'.length)).success &&
      resourceRef !== originalRef,
    'MUTATION_DISTINCT_RESOURCE',
  );
  return validateWorkItemReboundRead(
    record,
    actor,
    binding,
    'CREATE',
    record.result.operation.resourceRef,
    observed,
  );
}

export function validateWorkItemMutationProof(proof, record, transition) {
  validateWorkItemMutationRead(
    record,
    transition,
    record?.request?.resourceRef,
    record?.result,
    record?.result,
  );
  requireThat(
    ['context', 'logout'].includes(transition) &&
      record?.status === 202 &&
      record.result?.kind === 'OPERATION' &&
      record.request?.command === 'CREATE' &&
      proof?.state === 'PASS' &&
      proof.transition === transition &&
      proof.requestKey === record?.request?.requestKey &&
      proof.operationId === record?.result?.operation?.operationId &&
      proof.workItemRef === record?.result?.operation?.resourceRef &&
      proof.effects === 1 &&
      proof.uiCleared === true &&
      proof.reauthenticatedReadback === true,
    'MUTATION_PRIOR_UI_BLOCKED',
  );
  return proof;
}

export function workItemAssignedResume(records) {
  requireThat(Array.isArray(records) && records.length === 3, 'ASSIGNED_RECORDS');
  requireThat(
    [0, 1, 2].every((index) => Object.hasOwn(records, index)),
    'ASSIGNED_RECORDS',
  );
  if (records.every((record) => record === undefined)) return 'FRESH_INTENT';
  requireThat(
    records.every((record) => record && !Array.isArray(record) && record.status === 202),
    'ASSIGNED_ORIGINAL_OUTCOME_BLOCKED',
  );
  return 'READ_KNOWN';
}

export function workItemPopulationIntents(originalRef, initialRefs) {
  keyboardFollowupIntent(originalRef);
  requireThat(
    Array.isArray(initialRefs) &&
      initialRefs.every(
        (value) =>
          typeof value === 'string' &&
          value.startsWith('urn:openpc:resource:') &&
          workItemId.safeParse(value.slice('urn:openpc:resource:'.length)).success,
      ) &&
      new Set(initialRefs).size === initialRefs.length,
    'POPULATION_INITIAL_IDENTITIES',
  );
  requireThat(
    Array.from({ length: initialRefs.length }, (_, index) =>
      Object.hasOwn(initialRefs, index),
    ).every(Boolean),
    'POPULATION_INITIAL_IDENTITIES',
  );
  const purposes = [
    'participant visibility',
    'privacy isolation',
    'read authority',
    'creation authority',
    'resource linkage',
    'unassigned visibility',
    'assigned visibility',
    'open-state visibility',
    'completed-state visibility',
    'remediation classification',
    'ascending ordering',
    'descending ordering',
    'page-boundary continuation',
    'cursor integrity',
    'cursor query binding',
    'cursor session binding',
    'collection cardinality',
    'collection completeness',
    'empty-result visibility',
    'inspection without transition',
    'original operation identity',
    'signed transition binding',
    'outbox binding',
    'restart readback',
    'keyboard page navigation',
    'narrow-screen page navigation',
  ];
  return purposes.slice(0, Math.max(0, 26 - initialRefs.length)).map((purpose) =>
    Object.freeze({
      kind: 'REMEDIATION',
      resourceRef: originalRef,
      assigneeRef: null,
      reason: `Review ${purpose} for the completed work item in the populated remediation collection.`,
    }),
  );
}

export function workItemPopulationResume(records) {
  requireThat(
    Array.isArray(records) &&
      records.length <= 26 &&
      Array.from({ length: records.length }, (_, index) => Object.hasOwn(records, index)).every(
        Boolean,
      ),
    'POPULATION_RECORDS',
  );
  let missing = false;
  for (const record of records) {
    if (record === undefined) {
      missing = true;
      continue;
    }
    requireThat(
      !missing && record?.status === 202 && record.result?.kind === 'OPERATION',
      'POPULATION_ORIGINAL_OUTCOME_BLOCKED',
    );
  }
  return records.some((record) => record !== undefined) ? 'READ_KNOWN' : 'FRESH_INTENTS';
}

export function validateWorkItemPopulationRead(record, intent, binding, observed) {
  assert.deepEqual(
    intent,
    workItemPopulationIntents(intent?.resourceRef, []).find(
      (value) => value.reason === intent.reason,
    ),
    'WORK_ITEM_BROWSER_POPULATION_PLANNED_INTENT',
  );
  requireThat(
    record?.status === 202 && record.result?.kind === 'OPERATION',
    'POPULATION_ORIGINAL_OUTCOME_BLOCKED',
  );
  requireThat(
    record.result.operation.resourceRef !== intent.resourceRef,
    'POPULATION_DISTINCT_RESOURCE',
  );
  for (const [key, value] of Object.entries(intent))
    assert.deepEqual(record.request?.[key], value, 'WORK_ITEM_BROWSER_POPULATION_INTENT');
  return validateWorkItemReboundRead(
    record,
    'maker',
    binding,
    'CREATE',
    record.result.operation.resourceRef,
    observed,
  );
}

/** Selection from the actual Identity response only; never an authority grant. */
export function workItemAlternateContext(session, participantId, privacyDomainId) {
  requireThat(
    session?.authenticated === true &&
      session.contextMode === 'PARTICIPANT' &&
      session.participantId === participantId &&
      session.privacyDomainId === privacyDomainId &&
      Array.isArray(session.availableContexts),
    'ADVERTISED_CONTEXTS',
  );
  const distinct = new Set();
  for (const context of session.availableContexts) {
    requireThat(
      workItemId.safeParse(context.participantId).success &&
        workItemId.safeParse(context.privacyDomainId).success &&
        !distinct.has(context.privacyDomainId),
      'ADVERTISED_CONTEXTS',
    );
    distinct.add(context.privacyDomainId);
  }
  return session.availableContexts.find(
    (context) =>
      context.participantId === participantId && context.privacyDomainId !== privacyDomainId,
  );
}

export function validateNaturalWorkItemRecovery(record, stored) {
  const pending = workItemPending.parse(stored);
  requireThat(pending.uncertain && pending.operationId === undefined, 'NATURAL_RECOVERY_REQUIRED');
  assert.deepEqual(pending.request, record.request, 'WORK_ITEM_BROWSER_RECOVERY_REQUEST');
  return pending;
}

export function workItemFollowupResume(records) {
  requireThat(Array.isArray(records) && records.length === commands.length, 'FOLLOWUP_RECORDS');
  requireThat(
    records.every(
      (record) =>
        record === undefined ||
        (record !== null &&
          typeof record === 'object' &&
          !Array.isArray(record) &&
          record.status === 202),
    ),
    'FOLLOWUP_ORIGINAL_OUTCOME_UNRESOLVED',
  );
  requireThat(
    records.every(
      (record, index) =>
        record === undefined || records.slice(0, index).every((prior) => prior !== undefined),
    ),
    'FOLLOWUP_PARTIAL_ORDER',
  );
  return records.some((record) => record !== undefined) ? 'READ_KNOWN' : 'FRESH_INTENT';
}

export function validateWorkItemPriorUi(result, originalRef, keyboard, assigned) {
  requireThat(
    ['PASS', 'FAIL'].includes(result?.state) &&
      Array.isArray(result.gaps) &&
      result.gaps.length === 0 &&
      result.originalWorkItemRef === originalRef &&
      result.originalEffects === 4 &&
      result.followupEffects === 4 &&
      result.assignedEffects === 3,
    'PRIOR_UI_PHASE_REQUIRED',
  );
  requireThat(workItemFollowupResume(keyboard) === 'READ_KNOWN', 'PRIOR_UI_PHASE_REQUIRED');
  requireThat(workItemAssignedResume(assigned) === 'READ_KNOWN', 'PRIOR_UI_PHASE_REQUIRED');
  for (const [records, reference, operations] of [
    [keyboard, result.followupWorkItemRef, result.operations],
    [assigned, result.assignedWorkItemRef, result.assignedOperations],
  ]) {
    assert.deepEqual(
      operations,
      records.map((record) => record.result.operation.operationId),
    );
    requireThat(
      records.every((record) => record.result.operation.resourceRef === reference),
      'PRIOR_UI_PHASE_REQUIRED',
    );
  }
  // This result is emitted only after the mutation/control/visual phases finish.
  // FAIL retains the later context/logout failure; it never becomes a prior PASS.
  return result.state;
}

/** Explicit native identity, never an inferred newest row or a work-item fixture. */
export function parseNativeFleetSelection(value) {
  if (value === undefined) return undefined;
  let selected;
  try {
    selected = JSON.parse(value);
  } catch {
    /* Fail closed below. */
  }
  requireThat(
    selected &&
      typeof selected === 'object' &&
      !Array.isArray(selected) &&
      Object.keys(selected).sort().join(',') === 'candidateId,eventId,receiptId' &&
      Object.values(selected).every((id) => workItemId.safeParse(id).success),
    'NATIVE_FLEET_SELECTION_BLOCKED',
  );
  return selected;
}

export function parseNativeFleetMode(value, selection) {
  const mode = value ?? 'READ_ONLY';
  requireThat(['READ_ONLY', 'LIFECYCLE'].includes(mode), 'NATIVE_FLEET_MODE');
  requireThat(mode !== 'LIFECYCLE' || selection !== undefined, 'NATIVE_FLEET_SELECTION_REQUIRED');
  return mode;
}

/** Native production starts at revision 1, without a public CREATE or UPDATE. */
export function validateNativeFleetRequest(record, native, command) {
  requireThat(record && actorNames.includes(record.actor), 'NATIVE_FLEET_REQUEST_ACTOR');
  workItemBinding.parse(record.binding);
  const request = workItemCommand.parse(record.request);
  const revision = command === 'CLAIM' ? '1' : '2';
  requireThat(
    ['CLAIM', 'COMPLETE'].includes(command) &&
      request.command === command &&
      request.workItemRef === native.workItemRef &&
      request.expectedRevision === revision &&
      request.actorKey === record.binding?.actorKey &&
      workItemId.safeParse(record.binding?.actor?.principalRef?.slice(-36)).success &&
      request.etag ===
        `"sha256:${hash(
          Buffer.from(
            JSON.stringify({
              resourceId: native.workItemRef.slice(-36),
              revision,
            }),
          ),
        ).toString('hex')}"`,
    'NATIVE_FLEET_ORIGINAL_REQUEST',
  );
  requireThat(
    record.status === undefined || [202, 412].includes(record.status),
    'NATIVE_FLEET_OUTCOME',
  );
  if (record.status === 412)
    requireThat(record.result?.code === 'PC-DATA-6007', 'NATIVE_FLEET_DENIAL');
  if (record.status === 202) {
    const result = workItemView.parse(record.result);
    const responseBinding = workItemBinding.parse(record.readbackBinding ?? record.binding);
    requireThat(
      result.kind === 'OPERATION' &&
        isDeepStrictEqual(responseBinding.actor, record.binding.actor) &&
        isDeepStrictEqual(result.actor, record.binding.actor) &&
        result.actorKey === responseBinding.actorKey &&
        result.operation.resourceRef === native.workItemRef &&
        result.operation.actionIntentId === workItemActions[command] &&
        result.operation.idempotencyKey === `workbench-work-item-${request.requestKey}` &&
        result.operation.revision === String(BigInt(revision) + 1n) &&
        result.operation.state === 'SUCCEEDED' &&
        result.operation.truthState === 'SUCCESS',
      'NATIVE_FLEET_ORIGINAL_OPERATION',
    );
  } else if (record.status === undefined)
    requireThat(record.result === undefined, 'NATIVE_FLEET_UNKNOWN_OUTCOME');
  return record;
}

export function nativeFleetClaimWinner(records, native) {
  requireThat(
    records.length === 2 &&
      new Set(records.map((r) => r?.actor)).size === 2 &&
      new Set(records.map((r) => r?.binding?.actor?.principalRef)).size === 2,
    'NATIVE_FLEET_CLAIM_ACTORS',
  );
  for (const record of records) validateNativeFleetRequest(record, native, 'CLAIM');
  requireThat(
    records
      .map((r) => r.status)
      .sort()
      .join(',') === '202,412' && records[0].request.requestKey !== records[1].request.requestKey,
    'NATIVE_FLEET_CLAIM_CARDINALITY',
  );
  return records.find((r) => r.status === 202).actor;
}

export function validateNativeFleetOperation(record, native, binding, observed) {
  validateNativeFleetRequest(record, native, record.request.command);
  workItemBinding.parse({ actor: binding?.actor, actorKey: binding?.actorKey });
  requireThat(
    record.status !== 412 && isDeepStrictEqual(record.binding.actor, binding.actor),
    'NATIVE_FLEET_REBOUND_ACTOR',
  );
  const view = workItemView.parse(observed);
  requireThat(
    view.kind === 'OPERATION' &&
      view.actorKey === binding.actorKey &&
      isDeepStrictEqual(view.actor, binding.actor),
    'NATIVE_FLEET_OPERATION_SCOPE',
  );
  const recovered = {
    ...record,
    status: 202,
    result: view,
    readbackBinding: {
      actor: binding.actor,
      actorKey: binding.actorKey,
    },
  };
  validateNativeFleetRequest(recovered, native, record.request.command);
  if (record.status === 202)
    requireThat(
      isDeepStrictEqual(record.result.operation, view.operation),
      'NATIVE_FLEET_ORIGINAL_RESULT',
    );
  return recovered;
}

export function retainNativeFleetProof(original, observed) {
  if (original !== undefined)
    requireThat(isDeepStrictEqual(original, observed), 'NATIVE_FLEET_ORIGINAL_SIGNED_BYTES');
  return original ?? observed;
}

/** Only the selected Work Item and its exact signed transition rows may change.
 * Receipt crypto and operation bindings are checked by the real SQL caller. */
export function validateNativeFleetEffects(before, after, native, transitions) {
  const itemId = native.workItemRef.slice(-36);
  const itemTable = 'control.work_item',
    receiptTable = 'control.audit_occurrence',
    eventTable = 'control.outbox_event';
  requireThat(
    [itemTable, receiptTable, eventTable].every(
      (table) => Array.isArray(before[table]) && Array.isArray(after[table]),
    ),
    'NATIVE_FLEET_SNAPSHOT',
  );
  requireThat(
    transitions.length <= 2 &&
      new Set(transitions.map((t) => t.operationId)).size === transitions.length &&
      transitions.every(
        (t, i) =>
          t.command === ['CLAIM', 'COMPLETE'][i] &&
          workItemId.safeParse(t.principalId).success &&
          workItemId.safeParse(t.operationId).success &&
          (!i || t.principalId === transitions[0].principalId),
      ),
    'NATIVE_FLEET_TRANSITIONS',
  );
  requireThat(
    isDeepStrictEqual(Object.keys(before).sort(), Object.keys(after).sort()),
    'NATIVE_FLEET_SNAPSHOT',
  );
  for (const table of Object.keys(before)) {
    const selected = (entry) =>
      table === itemTable
        ? entry.retained.work_item_id === itemId
        : entry.retained.aggregate_id === itemId;
    if (![itemTable, receiptTable, eventTable].includes(table)) {
      validateNativeFleetUnchanged(before[table], after[table]);
      continue;
    }
    validateNativeFleetUnchanged(
      before[table].filter((r) => !selected(r)),
      after[table].filter((r) => !selected(r)),
    );
    const old = before[table].filter(selected),
      next = after[table].filter(selected);
    if (table !== itemTable) {
      requireThat(
        old.length === 0 && next.length === transitions.length,
        'NATIVE_FLEET_EFFECT_COUNT',
      );
      continue;
    }
    requireThat(old.length === 1 && next.length === 1, 'NATIVE_FLEET_ITEM_COUNT');
    const prior = old[0].retained,
      current = next[0].retained;
    requireThat(
      prior.state === 'OPEN' &&
        String(prior.row_version) === '1' &&
        prior.assignee_principal_id === null &&
        prior.claimed_by_principal_id === null &&
        prior.completed_by_principal_id === null,
      'NATIVE_FLEET_ORIGINAL_OPEN',
    );
    const changes = [
      'state',
      'row_version',
      'assignee_principal_id',
      'claimed_by_principal_id',
      'completed_by_principal_id',
      'updated_at',
    ];
    const fixed = (row) =>
      Object.fromEntries(Object.entries(row).filter(([key]) => !changes.includes(key)));
    validateNativeFleetUnchanged(fixed(prior), fixed(current));
    requireThat(
      current.state === ['OPEN', 'CLAIMED', 'COMPLETED'][transitions.length] &&
        String(current.row_version) === String(transitions.length + 1) &&
        current.assignee_principal_id === (transitions[0]?.principalId ?? null) &&
        current.claimed_by_principal_id === (transitions[0]?.principalId ?? null) &&
        current.completed_by_principal_id === (transitions[1]?.principalId ?? null),
      'NATIVE_FLEET_ITEM_TRANSITION',
    );
    if (!transitions.length) validateNativeFleetUnchanged(prior, current);
  }
}

/** SQL supplies these fields; this only checks their exact linkage, not authority. */
export function validateNativeFleetBinding(rows, selected, scope, mode = 'READ_ONLY') {
  requireThat(rows.length === 1, 'NATIVE_FLEET_BINDING_CARDINALITY_BLOCKED');
  const row = rows[0];
  requireThat(
    row.participantId === scope.participantId &&
      row.privacyDomainId === scope.privacyDomainId &&
      row.eventId === selected.eventId &&
      row.receiptId === selected.receiptId &&
      row.candidateId === selected.candidateId &&
      workItemId.safeParse(row.workItemId).success &&
      row.quarantineState === 'COMMITTED' &&
      row.kind === 'FLEET_FAILURE' &&
      (mode === 'READ_ONLY'
        ? row.state === 'OPEN' && row.revision === '1'
        : mode === 'LIFECYCLE' &&
          ['OPEN:1', 'CLAIMED:2', 'COMPLETED:3'].includes(`${row.state}:${row.revision}`)) &&
      row.resourceRef === ref(selected.candidateId) &&
      row.payloadMatches === true &&
      row.outboxMatches === true,
    'NATIVE_FLEET_BINDING_BLOCKED',
  );
  return { workItemRef: ref(row.workItemId), resourceRef: row.resourceRef };
}

export function validateNativeFleetRead(view, binding, native) {
  const parsed = workItemView.parse(view);
  requireThat(
    parsed.kind === 'DETAIL' &&
      parsed.actorKey === binding.actorKey &&
      isDeepStrictEqual(parsed.actor, binding.actor) &&
      parsed.workItem.workItemId === native.workItemRef &&
      parsed.workItem.resourceRef === native.resourceRef &&
      parsed.workItem.participantId === `urn:openpc:participant:${binding.actor.participantId}` &&
      parsed.workItem.kind === 'FLEET_FAILURE' &&
      parsed.workItem.state === 'OPEN' &&
      parsed.workItem.revision === '1' &&
      parsed.workItem.assigneeRef === null,
    'NATIVE_FLEET_PUBLIC_BINDING',
  );
  return parsed.workItem;
}

export function validateNativeFleetUnchanged(before, after) {
  // Never include signed bytes, private payload or producer material in failure output.
  requireThat(isDeepStrictEqual(before, after), 'NATIVE_FLEET_FORBIDDEN_EFFECT');
}

async function runNativeFleetLifecycle({
  selected,
  options,
  native,
  pool,
  pages,
  actors,
  read,
  waitResponse,
  expect,
  AxeBuilder,
  exec,
  artifacts,
  retainedRoot,
  kernel,
  verify,
  snapshot,
}) {
  const { participantId, privacyDomainId, compose } = options;
  const itemId = native.workItemRef.slice(-36);
  await mkdir(retainedRoot, { recursive: true, mode: 0o700 });
  const load = async (name) => {
    try {
      return JSON.parse(await readFile(join(retainedRoot, `${name}.json`), 'utf8'));
    } catch (error) {
      if (error.code === 'ENOENT') return undefined;
      throw error;
    }
  };
  const save = async (name, value) => {
    const path = join(retainedRoot, `${name}.json`),
      tmp = `${path}.${randomUUID()}.tmp`;
    await writeFile(tmp, JSON.stringify(value), { mode: 0o600, flag: 'wx' });
    await rename(tmp, path);
  };
  let baseline = await load('baseline');
  if (!baseline) {
    baseline = { selected, native, snapshot: await snapshot() };
    validateNativeFleetEffects(baseline.snapshot, baseline.snapshot, native, []);
    await save('baseline', baseline);
  }
  requireThat(
    isDeepStrictEqual(baseline.selected, selected) && isDeepStrictEqual(baseline.native, native),
    'NATIVE_FLEET_RETAINED_SELECTION',
  );
  const bindings = {};
  let blockedWrites = 0;
  const guard = async (route) => {
    if (route.request().method() === 'GET') return route.continue();
    blockedWrites++;
    await route.abort();
  };
  for (const name of actorNames) {
    await pages[name].route(`**${endpoint}*`, guard);
    bindings[name] = await read(pages[name], { view: 'LIST' });
    requireThat(
      bindings[name].actor.participantId === participantId &&
        bindings[name].actor.privacyDomainId === privacyDomainId &&
        bindings[name].actor.principalRef === ref(actors[name].principalId),
      'NATIVE_FLEET_ACTOR_SCOPE',
    );
  }
  const detail = async (name) => {
    const value = await read(pages[name], {
      view: 'DETAIL',
      actorKey: bindings[name].actorKey,
      workItemRef: native.workItemRef,
    });
    requireThat(
      value.actorKey === bindings[name].actorKey &&
        isDeepStrictEqual(value.actor, bindings[name].actor) &&
        value.workItem.workItemId === native.workItemRef &&
        value.workItem.resourceRef === native.resourceRef &&
        value.workItem.kind === 'FLEET_FAILURE',
      'NATIVE_FLEET_LIFECYCLE_DETAIL',
    );
    return value;
  };
  const inspect = async (name) => {
    const page = pages[name];
    await page
      .getByRole('combobox', { name: 'Filter field', exact: true })
      .selectOption('resourceRef');
    await page.getByLabel('Filter value', { exact: true }).fill(native.resourceRef);
    const listing = waitResponse(page, 'GET', 'LIST');
    await page.getByRole('button', { name: 'Refresh work items', exact: true }).click();
    requireThat((await listing).status() === 200, 'NATIVE_FLEET_REFRESH');
    const response = waitResponse(page, 'GET', 'DETAIL');
    await page.getByRole('button', { name: `Inspect ${native.workItemRef}`, exact: true }).click();
    requireThat((await response).status() === 200, 'NATIVE_FLEET_INSPECT');
    await expect(
      page.getByRole('heading', { name: 'Work-item details', exact: true }),
    ).toBeFocused();
    return detail(name);
  };
  const keyboard = async (page, button) => {
    await expect(button).toBeEnabled();
    for (let i = 0; i < 160; i++) {
      if (await button.evaluate((element) => element === document.activeElement)) {
        await page.keyboard.press('Enter');
        return;
      }
      await page.keyboard.press('Tab');
    }
    throw new Error('WORK_ITEM_BROWSER_NATIVE_FLEET_KEYBOARD_UNREACHABLE');
  };
  const visual = async (name, stage) => {
    for (const width of [1280, 390]) {
      await pages[name].setViewportSize({ width, height: 900 });
      requireThat(
        await pages[name].evaluate(() => document.documentElement.scrollWidth <= innerWidth),
        'NATIVE_FLEET_REFLOW',
      );
      requireThat(
        (await new AxeBuilder({ page: pages[name] }).include('main').analyze()).violations
          .length === 0,
        'NATIVE_FLEET_ACCESSIBILITY',
      );
      await pages[name].screenshot({
        path: join(artifacts, `${stage}-${width}.png`),
        fullPage: true,
      });
    }
  };
  // Discover only the original durable operation, then read it through the public
  // owner under current authority. Absence/ambiguity never authorizes resubmission.
  const reconcile = async (name, command) => {
    let record = await load(name);
    if (!record) return undefined;
    validateNativeFleetRequest(record, native, command);
    const binding = bindings[record.actor];
    requireThat(
      isDeepStrictEqual(record.binding.actor, binding.actor),
      'NATIVE_FLEET_REBOUND_ACTOR',
    );
    if (record.status === 412) return record;
    const rows = (
      await pool.query(
        `select operation_id::text as id,expected_aggregate_version::text as revision,terminal_state
       from control.idempotency_record where participant_id=$1 and privacy_domain_id=$2
       and principal_id=$3 and action_intent_id=$4 and catalog_operation_id=$5 and idempotency_key=$6`,
        [
          participantId,
          privacyDomainId,
          actors[record.actor].principalId,
          workItemActions[command],
          `CFG-OP-${command}-WORK-ITEM`,
          `workbench-work-item-${record.request.requestKey}`,
        ],
      )
    ).rows;
    requireThat(
      rows.length === 1 &&
        rows[0].terminal_state === 'COMMITTED' &&
        rows[0].revision === record.request.expectedRevision,
      'NATIVE_FLEET_ORIGINAL_OUTCOME_BLOCKED',
    );
    const observed = await read(pages[record.actor], {
      view: 'OPERATION',
      actorKey: binding.actorKey,
      operationId: rows[0].id,
    });
    const recovered = validateNativeFleetOperation(record, native, binding, observed);
    if (record.status === undefined) {
      record = recovered;
      await save(name, record);
    }
    return record;
  };
  const receipts = async (records) => {
    await verify();
    const accepted = records.filter((r) => r?.status === 202);
    const rows = (
      await pool.query(
        `select a.*,k.public_key_spki_der,e.principal_id::text as actor
       from control.audit_occurrence a join control.business_signing_key k using(participant_id,privacy_domain_id,signer_id)
       join control.mutation_evidence e on e.participant_id=a.participant_id and e.privacy_domain_id=a.privacy_domain_id
        and e.operation_id=a.operation_id and e.action_intent_id=a.action_intent_id
        and e.catalog_operation_id=a.catalog_operation_id and e.aggregate_id=a.aggregate_id
        and e.candidate_digest=a.candidate_digest
       where a.participant_id=$1 and a.privacy_domain_id=$2 and a.aggregate_type='work-item' and a.aggregate_id=$3
       order by a.after_revision`,
        [participantId, privacyDomainId, itemId],
      )
    ).rows;
    requireThat(rows.length === accepted.length, 'NATIVE_FLEET_SIGNED_EFFECT_COUNT');
    const transitions = [];
    for (const [index, row] of rows.entries()) {
      const command = ['CLAIM', 'COMPLETE'][index];
      const original = accepted.find((r) => r.request.command === command);
      requireThat(
        original &&
          row.operation_id === original.result.operation.operationId &&
          row.actor === actors[original.actor].principalId &&
          row.action_intent_id === workItemActions[command] &&
          kernel.verifyReceiptCose(row.public_key_spki_der, row.receipt_cbor, row.cose_sign1),
        'NATIVE_FLEET_SIGNED_OPERATION',
      );
      const receipt = kernel.decodeAdmittedReceipt(row.receipt_cbor);
      const profile = kernel.businessTransitionProfileForOperation(`CFG-OP-${command}-WORK-ITEM`);
      requireThat(
        profile &&
          row.catalog_operation_id === profile.catalogOperationId &&
          isDeepStrictEqual(
            row.profile_digest,
            Buffer.from(profile.profileDigest.slice(7), 'hex'),
          ) &&
          receipt.participantId === participantId &&
          receipt.privacyDomainId === privacyDomainId &&
          receipt.aggregateId === itemId &&
          receipt.aggregateType === 'work-item' &&
          receipt.operationId === row.operation_id &&
          receipt.receiptId === row.receipt_id &&
          receipt.catalogOperationId === profile.catalogOperationId &&
          receipt.transitionProfileId === profile.profileId &&
          receipt.transitionProfileVersion === profile.profileVersion &&
          isDeepStrictEqual(receipt.transitionProfileDigest, row.profile_digest) &&
          isDeepStrictEqual(receipt.candidateDigest, row.candidate_digest) &&
          receipt.actionIntentId === row.action_intent_id &&
          receipt.before.existence === 1 &&
          receipt.after.existence === 1 &&
          receipt.before.revision === BigInt(index + 1) &&
          receipt.after.revision === BigInt(index + 2) &&
          isDeepStrictEqual(hash(row.before_state_preimage), receipt.before.stateDigest) &&
          isDeepStrictEqual(hash(row.after_state_preimage), receipt.after.stateDigest) &&
          isDeepStrictEqual(row.before_state_digest, receipt.before.stateDigest) &&
          isDeepStrictEqual(row.after_state_digest, receipt.after.stateDigest) &&
          isDeepStrictEqual(hash(row.receipt_cbor), row.receipt_digest),
        'NATIVE_FLEET_SIGNED_STATE',
      );
      const events = (
        await pool.query(
          `select e.*,a.payload_cbor as signed_payload,a.payload_digest as signed_digest
         from control.outbox_event e join control.receipt_signing_attempt a
          on a.participant_id=e.participant_id and a.privacy_domain_id=e.privacy_domain_id and a.attempt_id=e.receipt_id
         where e.participant_id=$1 and e.privacy_domain_id=$2 and e.aggregate_id=$3
          and e.aggregate_type='work-item' and a.operation_id=$4 and e.receipt_id=$5`,
          [participantId, privacyDomainId, itemId, row.operation_id, row.receipt_id],
        )
      ).rows;
      const event = events[0];
      requireThat(
        events.length === 1 &&
          receipt.outboxEvents.length === 1 &&
          event.event_id === receipt.outboxEvents[0].eventId &&
          event.correlation_id === row.operation_id &&
          event.proof_kind === 'BUSINESS_RECEIPT_REFERENCE' &&
          event.sequence_namespace === 'CONTROL_BUSINESS_TRANSITION_V1' &&
          BigInt(event.business_sequence) === receipt.outboxEvents[0].aggregateSequence &&
          isDeepStrictEqual(hash(event.payload_cbor), receipt.outboxEvents[0].payloadDigest) &&
          isDeepStrictEqual(event.signed_payload, row.receipt_cbor) &&
          isDeepStrictEqual(event.signed_digest, row.receipt_digest),
        'NATIVE_FLEET_OUTBOX_BINDING',
      );
      const proof = {
        receiptId: row.receipt_id,
        payload: row.receipt_cbor.toString('base64'),
        cose: row.cose_sign1.toString('base64'),
        before: row.before_state_preimage.toString('base64'),
        after: row.after_state_preimage.toString('base64'),
        eventId: event.event_id,
        eventPayload: event.payload_cbor.toString('base64'),
        sequence: String(event.business_sequence),
      };
      const recordName = command === 'CLAIM' ? `claim-${original.actor}` : 'complete-winner';
      const retained = await load(recordName);
      requireThat(
        retained?.status === 202 && isDeepStrictEqual(retained.request, original.request),
        'NATIVE_FLEET_RETAINED_PROOF_REQUEST',
      );
      retainNativeFleetProof(retained.signedProof, proof);
      if (retained.signedProof === undefined)
        await save(recordName, { ...retained, signedProof: proof });
      transitions.push({ command, principalId: row.actor, operationId: row.operation_id });
    }
    validateNativeFleetEffects(baseline.snapshot, await snapshot(), native, transitions);
    requireThat(blockedWrites === 0, 'NATIVE_FLEET_UNEXPECTED_WRITE');
  };
  const capture = async (
    actor,
    name,
    command,
    action,
    { gate, lose = false, claimedVisual = false } = {},
  ) => {
    requireThat(!(await load(name)), 'NATIVE_FLEET_RESUBMISSION_FORBIDDEN');
    const page = pages[actor];
    let record,
      failure,
      finished = false,
      handled = false;
    const routeHandler = async (route) => {
      if (route.request().method() !== 'POST') return route.continue();
      try {
        requireThat(!handled, 'NATIVE_FLEET_DUPLICATE_DISPATCH');
        handled = true;
        record = {
          actor,
          binding: { actor: bindings[actor].actor, actorKey: bindings[actor].actorKey },
          request: workItemCommand.parse(route.request().postDataJSON()),
          ...(claimedVisual ? { claimedVisual: true } : {}),
        };
        validateNativeFleetRequest(record, native, command);
        await save(name, record); // Before any effect or network ambiguity.
        await gate?.();
        const response = await route.fetch();
        const body = await response.json();
        requireThat([202, 412].includes(response.status()), 'NATIVE_FLEET_MUTATION_OUTCOME');
        record = {
          ...record,
          status: response.status(),
          result: response.status() === 202 ? workItemView.parse(body) : { code: body.code },
        };
        validateNativeFleetRequest(record, native, command);
        await save(name, record);
        if (lose) {
          requireThat(record.status === 202, 'NATIVE_FLEET_COMMIT_BEFORE_LOSS');
          await route.abort('failed');
          record = { ...record, lostResponseObserved: true };
          await save(name, record);
        } else await route.fulfill({ response });
        finished = true;
      } catch (error) {
        failure = error;
        await route.abort('failed').catch(() => {});
      }
    };
    await page.route(`**${endpoint}`, routeHandler);
    try {
      await action();
      await expect.poll(() => finished || !!failure, { timeout: 30000 }).toBe(true);
      if (failure) throw failure;
      return record;
    } finally {
      await page.unroute(`**${endpoint}`, routeHandler);
    }
  };
  const recoverUi = async (record) => {
    const name = record.actor,
      page = pages[name];
    if (record.request.actorKey === bindings[name].actorKey) {
      await page.evaluate(
        ({ storageKey, request, operationId }) =>
          sessionStorage.setItem(
            storageKey,
            JSON.stringify({ request, operationId, uncertain: false }),
          ),
        { storageKey, request: record.request, operationId: record.result.operation.operationId },
      );
      await page.reload();
      const response = waitResponse(page, 'GET', 'OPERATION');
      await page.getByRole('button', { name: 'Recover original result', exact: true }).click();
      requireThat((await response).status() === 200, 'NATIVE_FLEET_READ_ORIGINAL');
    } else {
      // Natural session invalidation clears old-bound UI. Do not rewrite the old
      // request: read the known operation using the supported current-session form.
      await page.reload();
      await page
        .getByLabel('Existing operation ID', { exact: true })
        .fill(record.result.operation.operationId);
      const response = waitResponse(page, 'GET', 'OPERATION');
      await page.getByRole('button', { name: 'Read operation', exact: true }).click();
      requireThat((await response).status() === 200, 'NATIVE_FLEET_REBOUND_READ');
    }
    const response = waitResponse(page, 'GET', 'DETAIL');
    await page.getByRole('button', { name: 'Read operation work item', exact: true }).click();
    requireThat((await response).status() === 200, 'NATIVE_FLEET_EFFECT_READBACK');
    await expect(
      page.getByRole('region', { name: 'Original request recovery', exact: true }),
    ).toHaveCount(0);
  };
  let claims = await Promise.all(actorNames.map((name) => reconcile(`claim-${name}`, 'CLAIM')));
  requireThat(
    claims.every(Boolean) || claims.every((v) => v === undefined),
    'NATIVE_FLEET_PARTIAL_RACE_BLOCKED',
  );
  if (claims.every((v) => v === undefined)) {
    await receipts([]);
    for (const name of actorNames) {
      const current = await inspect(name);
      requireThat(
        current.workItem.state === 'OPEN' && current.workItem.revision === '1',
        'NATIVE_FLEET_CLAIM_PREREQUISITE',
      );
      await pages[name]
        .getByLabel('Transition reason', { exact: true })
        .fill('Claim handling of the quarantined Fleet delivery; no delivery retry.');
    }
    let arrivals = 0;
    const gate = async () => {
      arrivals++;
      await expect.poll(() => arrivals, { timeout: 10000 }).toBe(2);
    };
    const results = await Promise.allSettled(
      actorNames.map((name) =>
        capture(
          name,
          `claim-${name}`,
          'CLAIM',
          () =>
            keyboard(
              pages[name],
              pages[name].getByRole('button', { name: 'Claim work item', exact: true }),
            ),
          { gate },
        ),
      ),
    );
    const failed = results.filter((r) => r.status === 'rejected');
    if (failed.length)
      throw new AggregateError(
        failed.map((r) => r.reason),
        'Native Fleet claim race failed',
      );
    claims = results.map((r) => r.value);
  }
  const winner = nativeFleetClaimWinner(claims, native);
  const loser = actorNames.find((name) => name !== winner);
  const won = claims.find((r) => r.actor === winner);
  let complete = await reconcile('complete-winner', 'COMPLETE');
  await receipts(complete ? [won, complete] : [won]);
  await recoverUi(won);
  if (!complete) {
    const existingDenial = await reconcile('complete-loser', 'COMPLETE');
    if (!existingDenial) {
      const current = await detail(loser);
      requireThat(
        current.workItem.state === 'CLAIMED' && current.workItem.revision === '2',
        'NATIVE_FLEET_COMPLETE_PREREQUISITE',
      );
      const request = {
        command: 'COMPLETE',
        actorKey: bindings[loser].actorKey,
        requestKey: randomUUID(),
        workItemRef: native.workItemRef,
        expectedRevision: '2',
        etag: current.etag,
        reason: 'Verify that another actor cannot complete the claimant’s Fleet work item.',
      };
      const denial = await capture(loser, 'complete-loser', 'COMPLETE', () =>
        pages[loser].evaluate(
          async ({ endpoint, request }) => {
            await fetch(endpoint, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(request),
            });
          },
          { endpoint, request },
        ),
      );
      requireThat(denial.status === 412, 'NATIVE_FLEET_WRONG_ACTOR_COMPLETION');
    } else requireThat(existingDenial.status === 412, 'NATIVE_FLEET_WRONG_ACTOR_COMPLETION');
    await receipts([won]);
    await visual(winner, 'native-claimed');
    await pages[winner]
      .getByLabel('Transition reason', { exact: true })
      .fill('Complete Work Item handling only; delivery remains quarantined and unacknowledged.');
    complete = await capture(
      winner,
      'complete-winner',
      'COMPLETE',
      () =>
        keyboard(
          pages[winner],
          pages[winner].getByRole('button', { name: 'Complete work item', exact: true }),
        ),
      { lose: true, claimedVisual: true },
    );
  }
  requireThat(
    complete.actor === winner && complete.status === 202,
    'NATIVE_FLEET_COMPLETION_OWNER',
  );
  const deniedCompletion = await reconcile('complete-loser', 'COMPLETE');
  requireThat(
    deniedCompletion?.actor === loser && deniedCompletion.status === 412,
    'NATIVE_FLEET_DENIAL_EVIDENCE_REQUIRED',
  );
  await reconcile('complete-winner', 'COMPLETE');
  await receipts([won, complete]);
  await recoverUi(complete); // GET-only reconciliation after the deliberately lost ACK.
  const current = await detail(winner);
  requireThat(
    current.workItem.state === 'COMPLETED' &&
      current.workItem.revision === '3' &&
      current.workItem.assigneeRef === bindings[winner].actor.principalRef,
    'NATIVE_FLEET_COMPLETED_READBACK',
  );
  await visual(winner, 'native-completed');
  await exec(
    compose[0],
    [...compose.slice(1), 'restart', '--no-deps', 'control-api', 'admin-web'],
    { timeout: 90000, maxBuffer: 1024 * 1024 },
  );
  await expect
    .poll(
      async () => {
        try {
          return (await pages[winner].request.get(`${origin}${endpoint}?view=LIST`)).status();
        } catch {
          return 0;
        }
      },
      { timeout: 30000, intervals: [250, 500, 1000] },
    )
    .toBe(200);
  for (const name of actorNames) {
    await pages[name].reload();
    const rebound = await read(pages[name], { view: 'LIST' });
    requireThat(
      isDeepStrictEqual(rebound.actor, bindings[name].actor),
      'NATIVE_FLEET_RESTART_ACTOR',
    );
    bindings[name] = rebound;
  }
  await reconcile(`claim-${winner}`, 'CLAIM');
  await reconcile('complete-winner', 'COMPLETE');
  await recoverUi(complete);
  await receipts([won, complete]);
  await visual(winner, 'native-restart');
  requireThat(
    complete.claimedVisual === true && complete.lostResponseObserved === true,
    'NATIVE_FLEET_TRANSIENT_ACCEPTANCE_BLOCKED',
  );
}

async function inspectNativeFleet({
  selected,
  options,
  pool,
  Pool,
  pages,
  actors,
  read,
  waitResponse,
  expect,
  AxeBuilder,
  authenticate,
  exec,
  artifacts,
  mode = 'READ_ONLY',
  retainedRoot,
  kernel,
}) {
  const { participantId, privacyDomainId, secretRoot, compose } = options;
  const scope = [participantId, privacyDomainId];
  const facts = new Pool({
    host: '127.0.0.1',
    port: 55433,
    database: 'openpc_facts',
    user: 'openpc_facts',
    password: (await readFile(join(secretRoot, 'fact_pg_password.txt'), 'utf8')).trim(),
    max: 1,
    options: '-c default_transaction_read_only=on',
  });
  let phase = 'NATIVE_BINDING',
    state = 'BLOCKED',
    firstFailure,
    native,
    blockedWrites = 0;
  const bindings = {};
  const guard = async (route) => {
    if (route.request().method() !== 'GET') {
      blockedWrites++;
      await route.abort();
    } else await route.continue();
  };
  try {
    const worker = await exec(compose[0], [...compose.slice(1), 'ps', '-q', 'control-worker']);
    requireThat(worker.stdout.trim() === '', 'NATIVE_FLEET_EXCLUSIVE_CONSUMER_BLOCKED');
    const binding = (
      await pool.query(
        `select q.participant_id::text as "participantId",
      q.privacy_domain_id::text as "privacyDomainId",q.event_id::text as "eventId",
      q.receipt_id::text as "receiptId",d.candidate_id::text as "candidateId",
      q.work_item_id::text as "workItemId",q.state as "quarantineState",w.kind,w.state,
      w.row_version::text as revision,w.resource_ref as "resourceRef",
      (w.payload_digest=q.material_digest) as "payloadMatches",
      (o.receipt_digest=q.receipt_digest) as "outboxMatches"
      from control.fleet_fact_quarantine q
      left join control.fleet_fact_delivery d using(participant_id,privacy_domain_id,event_id)
      left join control.fleet_fact_failure_outbox o using(participant_id,privacy_domain_id,receipt_id)
      left join control.work_item w using(participant_id,privacy_domain_id,work_item_id)
      where q.participant_id=$1 and q.privacy_domain_id=$2 and q.event_id=$3 and q.receipt_id=$4`,
        [...scope, selected.eventId, selected.receiptId],
      )
    ).rows;
    native = validateNativeFleetBinding(binding, selected, options, mode);
    const verify = async () => {
      const rows = (
        await pool.query(
          `select q.claims,q.payload,q.cose,q.receipt_id::text as "receiptId",q.receipt_digest as "receiptDigest",
     o.receipt_digest as "outboxDigest",q.work_item_id::text as "workItemId",
     d.material,q.material_digest as "materialDigest",d.event_id::text as "eventId",
     d.candidate_id::text as "candidateId",d.generation_id::text as "generationId",d.fact_type as "factType",
     d.sequence::text,d.initial_profile_digest as "initialProfileDigest",d.failed_attempts as "failedAttempts",
     d.maximum_attempts as "maximumAttempts",d.lease_generation::text as "leaseGeneration",
     (d.state='QUARANTINED' and d.last_problem='PC-DATA-6005' and d.lease_id is null
      and d.material_digest=q.material_digest
      and (select count(*) from control.fleet_fact_delivery_attempt a where a.participant_id=d.participant_id
       and a.privacy_domain_id=d.privacy_domain_id and a.event_id=d.event_id)=d.lease_generation
      and (select count(*) from control.fleet_fact_delivery_attempt a where a.participant_id=d.participant_id
       and a.privacy_domain_id=d.privacy_domain_id and a.event_id=d.event_id
       and a.outcome in ('FAILED','LEASE_EXPIRED'))=d.failed_attempts
      and not exists(select 1 from control.fleet_fact_delivery_attempt a where a.participant_id=d.participant_id
       and a.privacy_domain_id=d.privacy_domain_id and a.event_id=d.event_id and a.outcome in ('ACTIVE','COMMITTED'))
     ) as "historyValid",q.committed_at_ms::text as "committedAtMs",q.signer_key_id as "signerKeyId",
     s.public_key_spki as "signerSpki",s.environment_id as "signerEnvironment",s.signer_role as "signerRole",
     s.purpose_code::text as "signerPurpose",s.database_role as "signerDatabaseRole",
     s.workload_credential_id::text as "signerCredentialId",s.workload_credential_epoch::text as "signerCredentialEpoch",
     s.valid_from_ms::text as "signerValidFrom",s.valid_until_ms::text as "signerValidUntil",
     p.claims as profile,p.payload as "profilePayload",p.cose as "profileCose",p.issuer_spki as "profileIssuer"
     from control.fleet_fact_quarantine q
     left join control.fleet_fact_delivery d using(participant_id,privacy_domain_id,event_id)
     left join control.fleet_fact_failure_outbox o using(participant_id,privacy_domain_id,receipt_id)
     left join control.fact_consumer_failure_signer s on s.participant_id=q.participant_id
      and s.privacy_domain_id=q.privacy_domain_id and s.consumer_id='LS-FLEET-CONTROL' and s.signer_key_id=q.signer_key_id
     left join control.fact_consumer_profile p on p.participant_id=q.participant_id and p.privacy_domain_id=q.privacy_domain_id
      and p.profile_digest=q.claims->>'currentProfileDigest' and p.consumer_id='LS-FLEET-CONTROL'
     where q.participant_id=$1 and q.privacy_domain_id=$2 and q.state='COMMITTED'
      and q.event_id=$3 and q.receipt_id=$4 and d.candidate_id=$5`,
          [...scope, selected.eventId, selected.receiptId, selected.candidateId],
        )
      ).rows;
      requireThat(rows.length === 1, 'NATIVE_FLEET_SIGNED_SOURCE_BLOCKED');
      const { verifyFactFailureSource } =
        await import('../../../services/control-api/src/evidence/fact-failure-source.ts');
      verifyFactFailureSource(rows[0], { participantId, privacyDomainId });
      const pending = (
        await facts.query(
          `select o.delivery_state,
        exists(select 1 from facts.control_admission_custody_ack a where a.participant_id=o.participant_id
          and a.privacy_domain_id=o.privacy_domain_id and a.candidate_id=o.candidate_id) as acknowledged
        from facts.outbox o where participant_id=$1 and privacy_domain_id=$2 and candidate_id=$3`,
          [...scope, selected.candidateId],
        )
      ).rows;
      requireThat(
        pending.length === 1 &&
          pending[0].delivery_state === 'PENDING' &&
          pending[0].acknowledged === false,
        'NATIVE_FLEET_PRODUCER_PENDING_BLOCKED',
      );
      const source = (
        await facts.query(
          `select f.generation_id::text,e.event_id::text,e.envelope
        from facts.canonical_fact f join facts.admission_delivery_event e using(participant_id,privacy_domain_id,candidate_id)
        where f.participant_id=$1 and f.privacy_domain_id=$2 and f.candidate_id=$3`,
          [...scope, selected.candidateId],
        )
      ).rows;
      requireThat(
        source.length === 1 &&
          source[0].event_id === selected.eventId &&
          source[0].generation_id === rows[0].generationId &&
          isDeepStrictEqual(
            source[0].envelope,
            JSON.parse(rows[0].material.toString('utf8')).envelope,
          ),
        'NATIVE_FLEET_FACT_SOURCE_BLOCKED',
      );
      for (const [client, table] of [
        [pool, 'control.fleet_fact_admission_inbox'],
        [facts, 'facts.fleet_admission_ack'],
      ]) {
        requireThat(
          (
            await client.query(
              `select 1 from ${table} where participant_id=$1 and privacy_domain_id=$2 and event_id=$3`,
              [...scope, selected.eventId],
            )
          ).rows.length === 0,
          'NATIVE_FLEET_ADMISSION_FORBIDDEN',
        );
      }
    };
    const snapshot = async () => {
      const result = {};
      // All scoped Work Items protect existing ordinary/assigned/mutation/population effects
      // without requiring any of those scenarios to have run in this independent branch.
      for (const [client, tables] of [
        [
          pool,
          [
            'control.fleet_fact_quarantine',
            'control.fleet_fact_failure_outbox',
            'control.fleet_fact_delivery',
            'control.fleet_fact_delivery_attempt',
            'control.fleet_fact_admission_inbox',
            'control.fleet_fact_admission_cursor',
            'control.work_item',
            'control.audit_occurrence',
            'control.outbox_event',
          ],
        ],
        [
          facts,
          [
            'facts.canonical_fact',
            'facts.admission_delivery_event',
            'facts.outbox',
            'facts.control_admission_custody_ack',
            'facts.fleet_admission_ack',
          ],
        ],
      ]) {
        for (const table of tables) {
          const suffix = ['control.audit_occurrence', 'control.outbox_event'].includes(table)
            ? " and aggregate_type='work-item'"
            : '';
          result[table] = (
            await client.query(
              `select to_jsonb(t) as retained from ${table} t
            where participant_id=$1 and privacy_domain_id=$2${suffix} order by to_jsonb(t)::text`,
              scope,
            )
          ).rows;
        }
      }
      return result;
    };
    await verify();
    if (mode === 'LIFECYCLE') {
      phase = 'NATIVE_LIFECYCLE';
      state = 'FAIL';
      await runNativeFleetLifecycle({
        selected,
        options,
        native,
        pool,
        pages,
        actors,
        read,
        waitResponse,
        expect,
        AxeBuilder,
        exec,
        artifacts,
        retainedRoot,
        kernel,
        verify,
        snapshot,
      });
      phase = 'NATIVE_LIFECYCLE_COMPLETE';
      state = 'PASS';
    } else {
      const before = await snapshot();
      const unchanged = async () => {
        requireThat(blockedWrites === 0, 'NATIVE_FLEET_WRITE_ATTEMPT');
        await verify();
        validateNativeFleetUnchanged(before, await snapshot());
      };
      state = 'FAIL';
      phase = 'BROWSER_INSPECTION';
      for (const name of actorNames) {
        await pages[name].route(`**${endpoint}*`, guard);
        bindings[name] = await read(pages[name], { view: 'LIST' });
        requireThat(
          bindings[name].actor.participantId === participantId &&
            bindings[name].actor.privacyDomainId === privacyDomainId &&
            bindings[name].actor.principalRef === ref(actors[name].principalId),
          'NATIVE_FLEET_ACTOR_SCOPE',
        );
      }
      const { maker } = pages;
      const keyboard = async (target) => {
        await expect(target).toHaveCount(1);
        for (let i = 0; i < 160; i++) {
          if (await target.evaluate((element) => element === document.activeElement)) return;
          await maker.keyboard.press('Tab');
        }
        throw new Error('WORK_ITEM_BROWSER_NATIVE_FLEET_KEYBOARD_UNREACHABLE');
      };
      let imageIndex = 0;
      const visual = async (name, page = maker) => {
        await page.setViewportSize({ width: 390, height: 844 });
        requireThat(
          await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
          'NATIVE_FLEET_REFLOW',
        );
        const violations = (await new AxeBuilder({ page }).include('main').analyze()).violations;
        requireThat(violations.length === 0, 'NATIVE_FLEET_ACCESSIBILITY');
        await page.screenshot({
          path: join(artifacts, `${++imageIndex}-${name}.png`),
          fullPage: true,
        });
        await page.setViewportSize({ width: 1280, height: 900 });
      };
      const walk = async () => {
        await maker
          .getByRole('combobox', { name: 'Filter field', exact: true })
          .selectOption('kind');
        await maker.getByLabel('Filter value', { exact: true }).fill('FLEET_FAILURE');
        let pending = waitResponse(maker, 'GET', 'LIST');
        await keyboard(maker.getByRole('button', { name: 'Refresh work items', exact: true }));
        await maker.keyboard.press('Enter');
        const seen = new Set(),
          cursors = new Set();
        let found = 0,
          total,
          revision;
        for (;;) {
          const response = await pending;
          requireThat(
            response.status() === 200 &&
              new URL(response.url()).searchParams.get('filter') === 'kind:eq:FLEET_FAILURE',
            'NATIVE_FLEET_KIND_QUERY',
          );
          const listing = workItemView.parse(await response.json());
          requireThat(
            listing.kind === 'LIST' &&
              listing.actorKey === bindings.maker.actorKey &&
              isDeepStrictEqual(listing.actor, bindings.maker.actor) &&
              listing.page.completeness === 'COMPLETE' &&
              listing.page.total !== null,
            'NATIVE_FLEET_LIST_SCOPE',
          );
          total ??= listing.page.total;
          revision ??= listing.page.snapshotRevision;
          requireThat(
            total === listing.page.total && revision === listing.page.snapshotRevision,
            'NATIVE_FLEET_LIST_SNAPSHOT',
          );
          for (const item of listing.page.items) {
            requireThat(
              item.kind === 'FLEET_FAILURE' && !seen.has(item.workItemId),
              'NATIVE_FLEET_LIST_ROW',
            );
            seen.add(item.workItemId);
            if (item.workItemId === native.workItemRef) {
              found++;
              pending = waitResponse(maker, 'GET', 'DETAIL');
              await keyboard(
                maker.getByRole('button', { name: `Inspect ${native.workItemRef}`, exact: true }),
              );
              await maker.keyboard.press('Enter');
              const detailResponse = await pending;
              requireThat(detailResponse.status() === 200, 'NATIVE_FLEET_UI_DETAIL');
              const detail = await detailResponse.json();
              validateNativeFleetRead(detail, bindings.maker, native);
              requireThat(isDeepStrictEqual(item, detail.workItem), 'NATIVE_FLEET_LIST_DETAIL');
              await expect(
                maker.getByRole('heading', { name: 'Work-item details', exact: true }),
              ).toBeFocused();
              const region = maker.getByRole('region', { name: 'Work-item details', exact: true });
              for (const value of [native.workItemRef, native.resourceRef, 'FLEET_FAILURE', 'OPEN'])
                await expect(region.getByText(value, { exact: true })).toBeVisible();
              await visual('native-detail');
            }
          }
          if (listing.page.nextCursor === null) break;
          requireThat(!cursors.has(listing.page.nextCursor), 'NATIVE_FLEET_CURSOR_REPEAT');
          cursors.add(listing.page.nextCursor);
          pending = waitResponse(maker, 'GET', 'LIST');
          await keyboard(maker.getByRole('button', { name: 'Next page', exact: true }));
          await maker.keyboard.press('Enter');
        }
        requireThat(
          found === 1 && BigInt(seen.size) === BigInt(total),
          'NATIVE_FLEET_LIST_MEMBERSHIP_BLOCKED',
        );
      };
      await walk();
      await unchanged();
      phase = 'CONTEXT_DENIALS';
      const denied = async (actorKey) => {
        const response = await maker.request.get(
          `${origin}${endpoint}?${new URLSearchParams({
            view: 'DETAIL',
            actorKey,
            workItemRef: native.workItemRef,
          })}`,
        );
        requireThat(
          response.status() === 404 && (await response.json()).code === 'PC-AUTH-0005',
          'NATIVE_FLEET_CONTEXT_DENIAL',
        );
      };
      await denied(bindings.checker.actorKey);
      const old = bindings.maker;
      // This tab retains a real old UI binding while the existing authenticator
      // reauthenticates its sibling through the actual Identity owner.
      const stalePage = await maker.context().newPage();
      await stalePage.route(`**${endpoint}*`, guard);
      await stalePage.goto(`${origin}/operate/support?view=work-items`);
      await stalePage
        .getByRole('combobox', { name: 'Filter field', exact: true })
        .selectOption('resourceRef');
      await stalePage.getByLabel('Filter value', { exact: true }).fill(native.resourceRef);
      const staleListResponse = waitResponse(stalePage, 'GET', 'LIST');
      await stalePage.getByRole('button', { name: 'Refresh work items', exact: true }).click();
      const staleList = workItemView.parse(await (await staleListResponse).json());
      requireThat(
        staleList.kind === 'LIST' &&
          staleList.actorKey === old.actorKey &&
          staleList.page.items.some((item) => item.workItemId === native.workItemRef),
        'NATIVE_FLEET_STALE_UI_PREREQUISITE',
      );
      const oldCookie = (await maker.context().cookies(origin)).find(
        (entry) => entry.name === 'openpc_local_runtime_session',
      );
      requireThat(!!oldCookie?.value, 'NATIVE_FLEET_ORIGINAL_SESSION');
      // The sign-in helper starts from an unauthenticated browser. Revoke through
      // the public owner while the sibling tab retains its original UI binding.
      const revoked = await maker.evaluate(
        async () => (await fetch('/api/v1/ui/local-session', { method: 'DELETE' })).status,
      );
      requireThat(revoked === 202, 'NATIVE_FLEET_SESSION_REVOCATION');
      const oldSession = await maker.request.get(`${origin}/api/v1/ui/local-session`, {
        headers: { Cookie: `${oldCookie.name}=${oldCookie.value}` },
      });
      requireThat(
        oldSession.status() === 200 && (await oldSession.json()).authenticated === false,
        'NATIVE_FLEET_ORIGINAL_SESSION_REVOKED',
      );
      await authenticate(maker, 'viewer', privacyDomainId, {
        participantWorkbench: false,
        expectedPrincipalId: old.actor.principalId,
      });
      await maker.goto(`${origin}/operate/support?view=work-items`);
      bindings.maker = await read(maker, { view: 'LIST' });
      requireThat(
        bindings.maker.actorKey !== old.actorKey &&
          isDeepStrictEqual(bindings.maker.actor, old.actor),
        'NATIVE_FLEET_REAUTHENTICATED_OWNER',
      );
      await denied(old.actorKey);
      validateNativeFleetRead(
        await read(maker, {
          view: 'DETAIL',
          actorKey: bindings.maker.actorKey,
          workItemRef: native.workItemRef,
        }),
        bindings.maker,
        native,
      );
      // Real focus/visibility changes clear the sibling tab before it can submit
      // an old binding. The direct old-binding denial above still exercises the
      // owner; do not fabricate a stale UI control after the product removes it.
      await expect(
        stalePage.getByRole('button', { name: `Inspect ${native.workItemRef}`, exact: true }),
      ).toHaveCount(0);
      await expect(
        stalePage.getByRole('region', { name: 'Work-item details', exact: true }),
      ).toHaveCount(0);
      await expect(stalePage.getByLabel('Filter value', { exact: true })).toHaveValue('');
      await visual('native-context-cleared', stalePage);
      await stalePage.close();
      await walk();
      await unchanged();
      phase = 'RESTART_READBACK';
      await exec(
        compose[0],
        [...compose.slice(1), 'restart', '--no-deps', 'control-api', 'admin-web'],
        { timeout: 90000, maxBuffer: 1024 * 1024 },
      );
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
      await maker.reload();
      const rebound = await read(maker, { view: 'LIST' });
      requireThat(
        isDeepStrictEqual(rebound.actor, bindings.maker.actor),
        'NATIVE_FLEET_RESTART_ACTOR',
      );
      bindings.maker = rebound;
      await walk();
      await unchanged();
      state = 'PASS';
      phase = 'READ_ONLY_INSPECTION_COMPLETE';
    }
  } catch (error) {
    firstFailure = error;
  } finally {
    const cleanup = await Promise.allSettled([facts.end()]);
    if (!firstFailure && cleanup.some((result) => result.status === 'rejected')) {
      firstFailure = new Error('WORK_ITEM_BROWSER_NATIVE_FLEET_CLEANUP_FAILED');
      state = 'FAIL';
      phase = 'CLEANUP';
    }
    try {
      await writeFile(
        join(artifacts, 'result.json'),
        JSON.stringify({
          state,
          phase,
          firstFailure: firstFailure
            ? { phase, code: 'NATIVE_INSPECTION_FAILED_OR_BLOCKED' }
            : undefined,
          selection: selected,
          mode,
          native,
          lifecycle:
            mode === 'LIFECYCLE' ? (state === 'PASS' ? 'COMPLETED' : 'UNRESOLVED') : 'OPEN',
          visualInspection: 'PENDING_INTEGRATOR',
          businessEffectsExpected: mode === 'LIFECYCLE' ? 2 : 0,
        }),
        { mode: 0o600, flag: 'wx' },
      );
    } catch {
      firstFailure ??= new Error('WORK_ITEM_BROWSER_NATIVE_FLEET_RESULT_FAILED');
    }
  }
  if (firstFailure) throw firstFailure;
}

async function main() {
  const options = parseWorkItemBrowserArguments(process.argv.slice(2));
  const { secretRoot, evidenceRoot, participantId, privacyDomainId, compose } = options;
  const nativeSelection = parseNativeFleetSelection(process.env.OPENPC_WORK_ITEM_NATIVE_FLEET);
  const nativeMode = parseNativeFleetMode(
    process.env.OPENPC_WORK_ITEM_NATIVE_FLEET_MODE,
    nativeSelection,
  );
  const exec = promisify(execFile);
  await exec('bash', [
    'scripts/maintenance/run-bounded.sh',
    '--profile',
    'runtime-target',
    '--reuse',
    '--',
    'true',
  ]);
  const [
    { expect },
    { default: AxeBuilder },
    { Pool },
    { withTransactionBrowser },
    kernel,
    { authenticate },
  ] = await Promise.all([
    import('@playwright/test'),
    import('@axe-core/playwright'),
    import('pg'),
    import('./transaction-workbench-browser.mjs'),
    import('../../../packages/security-kernel/src/index.ts'),
    import('./participant-workbench-browser.mjs'),
  ]);
  const artifacts = join(evidenceRoot, 'work-item-browser');
  const browserArtifacts = nativeSelection
    ? join(artifacts, `native-fleet-${nativeSelection.eventId}-${Date.now()}-${randomUUID()}`)
    : artifacts;
  await mkdir(browserArtifacts, { recursive: true, mode: 0o700 });
  await mkdir(artifacts, { recursive: true, mode: 0o700 });
  // Integrator invokes the existing actor bootstrap with its work-item mode into
  // this directory. The driver cannot grant roles or fall back to notification actors.
  const initialActors = validateWorkItemActors(
    JSON.parse(await readFile(join(artifacts, 'deployment-intent-actors.json'), 'utf8')),
    secretRoot,
    privacyDomainId,
  );
  const pool = new Pool({
    host: '127.0.0.1',
    port: 55432,
    database: 'openpc_control',
    user: 'openpc_control',
    password: (await readFile(join(secretRoot, 'control_pg_password.txt'), 'utf8')).trim(),
    max: 1,
    ...(nativeSelection ? { options: '-c default_transaction_read_only=on' } : {}),
  });
  const load = async (name) => {
    try {
      return JSON.parse(await readFile(join(artifacts, `${name}.json`), 'utf8'));
    } catch (error) {
      if (error.code === 'ENOENT') return undefined;
      throw error;
    }
  };
  const save = async (name, value) => {
    const path = join(artifacts, `${name}.json`),
      temporary = `${path}.${randomUUID()}.tmp`;
    await writeFile(temporary, JSON.stringify(value), { mode: 0o600, flag: 'wx' });
    await rename(temporary, path);
  };
  try {
    // Connected preflight is read-only. Existing runtime role/session/receipt owners
    // remain the actual authorization boundary when the UI calls them below.
    const requiredActions = [
      ...(nativeSelection
        ? nativeMode === 'LIFECYCLE'
          ? [workItemActions.CLAIM, workItemActions.COMPLETE]
          : []
        : Object.values(workItemActions)),
      'ACT-WORK_ITEMS_READ_COLLECTION-V1',
      'ACT-WORK_ITEMS_READ_RESOURCE-V1',
      ...(nativeSelection && nativeMode === 'READ_ONLY'
        ? []
        : ['ACT-OPERATIONS_READ_OPERATION-V1']),
    ];
    for (const actor of Object.values(initialActors)) {
      const row = (
        await pool.query(
          `select e.action_intent_ids,a.action_intent_ids assignment_actions,r.action_intent_ids role_actions from control.authority_envelope e
        join control.principal p on p.participant_id=e.participant_id and p.principal_id=e.principal_id
        join control.credential c on c.participant_id=p.participant_id and c.principal_id=p.principal_id
        join control.assignment a on a.participant_id=p.participant_id and a.principal_id=p.principal_id and a.authority_envelope_id=e.authority_envelope_id
        join control.authority_role r on r.participant_id=a.participant_id and r.role_id=a.role_id
        where e.participant_id=$1 and e.authority_envelope_id=$2 and p.principal_id=$3 and c.credential_id=$4
        and a.assignment_id=$5 and a.state='ACTIVE' and a.valid_during @> clock_timestamp()
        and $6=any(e.privacy_domain_ids) and $6=any(a.privacy_domain_ids)
        and e.state='ACTIVE' and p.state='ACTIVE' and c.state='ACTIVE'`,
          [
            participantId,
            actor.envelopeId,
            actor.principalId,
            actor.credentialId,
            actor.assignmentId,
            privacyDomainId,
          ],
        )
      ).rows;
      requireThat(
        row.length === 1 &&
          requiredActions.every((a) =>
            ['action_intent_ids', 'assignment_actions', 'role_actions'].every((field) =>
              row[0][field].includes(a),
            ),
          ),
        'ACTOR_ACTION_PREFLIGHT',
      );
    }
    const profiles = (
      nativeSelection ? (nativeMode === 'LIFECYCLE' ? ['CLAIM', 'COMPLETE'] : []) : commands
    ).map((command) => kernel.businessTransitionProfileForOperation(`CFG-OP-${command}-WORK-ITEM`));
    requireThat(
      profiles.every((p) => p?.aggregateType === 'work-item'),
      'PROFILE_PREFLIGHT',
    );
    for (const profile of profiles) {
      const rows = (
        await pool.query(
          `select k.signer_id from control.business_signing_selection s
        join control.business_signing_key k using(participant_id,privacy_domain_id,signer_id)
        join control.business_signing_key_state st using(participant_id,privacy_domain_id,signer_id)
        join control.business_signing_grant g using(participant_id,privacy_domain_id,signer_id)
        where s.participant_id=$1 and s.privacy_domain_id=$2 and s.environment_id='local'
        and s.profile_digest=$3 and g.profile_digest=$3 and st.state='ACTIVE'
        and k.valid_from_ns <= (extract(epoch from clock_timestamp())*1000000000)::numeric
        and k.valid_until_ns > (extract(epoch from clock_timestamp())*1000000000)::numeric`,
          [participantId, privacyDomainId, Buffer.from(profile.profileDigest.slice(7), 'hex')],
        )
      ).rows;
      requireThat(rows.length === 1, 'SIGNING_SELECTION_PREFLIGHT');
    }
    await withTransactionBrowser(
      {
        secretRoot,
        evidenceRoot: artifacts,
        artifacts: browserArtifacts,
        privacyDomainId,
        reuseSessions: true,
        route: '/operate/support?view=work-items',
        readyHeading: 'Work items',
      },
      async ({ maker, checker, actors }) => {
        validateWorkItemActors(actors, secretRoot, privacyDomainId);
        const pages = { maker, checker },
          bindings = {};
        const waitResponse = (page, method, view) => {
          const pending = page.waitForResponse((response) => {
            const url = new URL(response.url());
            return (
              url.pathname === endpoint &&
              response.request().method() === method &&
              (method !== 'GET' || url.searchParams.get('view') === view)
            );
          });
          // The matching UI action can fail before this waiter is awaited.
          // Preserve that first failure and browser artifacts instead of an
          // unhandled rejection terminating the process during cleanup.
          void pending.catch(() => {});
          return pending;
        };
        const read = async (page, parameters) => {
          const response = await page.request.get(
            `${origin}${endpoint}?${new URLSearchParams(parameters)}`,
          );
          requireThat(
            response.status() === 200 && response.headers()['cache-control'] === 'no-store',
            'PUBLIC_READ',
          );
          const parsed = workItemView.safeParse(await response.json());
          requireThat(parsed.success && parsed.data.kind === parameters.view, 'PUBLIC_READ_SHAPE');
          return parsed.data;
        };
        const refresh = async (page) => {
          const pending = waitResponse(page, 'GET', 'LIST');
          await page.getByRole('button', { name: 'Refresh work items', exact: true }).click();
          requireThat((await pending).status() === 200, 'REFRESH');
        };
        const inspect = async (name, itemRef) => {
          const page = pages[name];
          const pending = waitResponse(page, 'GET', 'DETAIL');
          await page.getByRole('button', { name: `Inspect ${itemRef}`, exact: true }).click();
          const response = await pending;
          requireThat(response.status() === 200, 'DETAIL');
          const detail = workItemView.parse(await response.json());
          requireThat(
            detail.kind === 'DETAIL' &&
              detail.workItem.workItemId === itemRef &&
              detail.actorKey === bindings[name].actorKey,
            'DETAIL_BINDING',
          );
          await expect(
            page.getByRole('heading', { name: 'Work-item details', exact: true }),
          ).toBeFocused();
          requireThat(
            !('payloadDigest' in detail.workItem) && !('reason' in detail.workItem),
            'PUBLIC_FIELD_PRIVACY',
          );
          return detail;
        };
        if (nativeSelection) {
          await inspectNativeFleet({
            selected: nativeSelection,
            options,
            pool,
            Pool,
            pages,
            actors,
            read,
            waitResponse,
            expect,
            AxeBuilder,
            authenticate,
            exec,
            artifacts: browserArtifacts,
            mode: nativeMode,
            retainedRoot: join(artifacts, `native-fleet-lifecycle-${nativeSelection.eventId}`),
            kernel,
          });
          return;
        }
        for (const name of actorNames) {
          const page = pages[name];
          await page.getByRole('link', { name: 'Work items', exact: true }).click();
          await expect(
            page.getByRole('heading', { name: 'Work items', exact: true }),
          ).toBeVisible();
          await expect(
            page.getByRole('button', { name: 'Create work item', exact: true }),
          ).toBeVisible();
          bindings[name] = await read(page, { view: 'LIST' });
          requireThat(
            bindings[name].actor.participantId === participantId &&
              bindings[name].actor.privacyDomainId === privacyDomainId &&
              bindings[name].actor.principalRef === ref(actors[name].principalId),
            'LIVE_ACTOR_SCOPE',
          );
          for (const name of ['Kind', 'Filter field', 'Sort'])
            await expect(page.getByRole('combobox', { name, exact: true })).toHaveCount(1);
          for (const label of ['Resource reference', 'Assignee reference (optional)', 'Reason'])
            await expect(page.getByLabel(label, { exact: true })).toHaveCount(1);
        }

        // Every request is retained before forwarding. A crash between send and save
        // leaves only the exact original request eligible for explicit recovery.
        const capture = async (name, file, command, click, { lose = false, gate } = {}) => {
          const page = pages[name];
          let record,
            failure,
            handled = false,
            finished = false;
          const routeHandler = async (route) => {
            if (route.request().method() !== 'POST') return route.continue();
            try {
              requireThat(!handled, 'DUPLICATE_UI_SUBMISSION');
              handled = true;
              const request = workItemCommand.parse(route.request().postDataJSON());
              requireThat(
                request.command === command && request.actorKey === bindings[name].actorKey,
                'UI_COMMAND',
              );
              const prior = await load(file);
              if (prior)
                assert.deepEqual(prior.request, request, 'Original request must be preserved');
              record = { actor: name, request };
              if (!prior) await save(file, record);
              await gate?.();
              const actual = await route.fetch();
              const body = await actual.json();
              requireThat([202, 412].includes(actual.status()), 'OWNER_MUTATION');
              record = {
                ...record,
                status: actual.status(),
                result: actual.status() === 202 ? workItemView.parse(body) : { code: body.code },
              };
              record = reconcileWorkItemCapture(prior, record);
              if (prior?.status === undefined) await save(file, record);
              if (lose) {
                requireThat(actual.status() === 202, 'COMMIT_BEFORE_LOSS');
                await route.abort('failed');
              } else await route.fulfill({ response: actual });
              finished = true;
            } catch (error) {
              failure = error;
              await route.abort('failed').catch(() => {});
            }
          };
          await page.route(`**${endpoint}`, routeHandler);
          try {
            await click();
            await expect.poll(() => !!failure || finished, { timeout: 30000 }).toBe(true);
            if (failure) throw failure;
            await expect(
              page.getByRole('button', { name: 'Recover original result', exact: true }),
            ).toBeVisible();
            return record;
          } finally {
            await page.unroute(`**${endpoint}`, routeHandler);
          }
        };
        const browserPost = async (page, request) =>
          page.evaluate(
            async ({ endpoint, request }) => {
              const response = await fetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(request),
              });
              return { status: response.status, body: await response.json() };
            },
            { endpoint, request },
          );
        const recover = async (name, file, command, itemRef, forceLost = false) => {
          const retained = await load(file);
          if (retained?.status === 202 && retained.request.actorKey !== bindings[name].actorKey) {
            const observed = await read(pages[name], {
              view: 'OPERATION',
              actorKey: bindings[name].actorKey,
              operationId: retained.result.operation.operationId,
            });
            const original = validateWorkItemReboundRead(
              retained,
              name,
              bindings[name],
              command,
              itemRef,
              observed,
            );
            await refresh(pages[name]);
            await inspect(name, original.result.operation.resourceRef);
            return original;
          }
          let record = validateWorkItemRecord(retained, name, bindings[name], command, itemRef);
          if (record.status === 412) return record;
          const page = pages[name];
          const knownOperation =
            record.result &&
            (await read(page, {
              view: 'OPERATION',
              actorKey: bindings[name].actorKey,
              operationId: record.result.operation.operationId,
            }));
          workItemResumeAction(record, knownOperation);
          await page.evaluate(
            ({ request, operationId, storageKey }) =>
              sessionStorage.setItem(
                storageKey,
                JSON.stringify({
                  request,
                  ...(operationId ? { operationId } : {}),
                  uncertain: !operationId,
                }),
              ),
            {
              request: record.request,
              operationId: forceLost ? undefined : record.result?.operation.operationId,
              storageKey,
            },
          );
          await page.reload();
          await expect(
            page.getByRole('button', { name: 'Recover original result', exact: true }),
          ).toBeEnabled();
          if (!record.result || forceLost) {
            record = await capture(name, file, command, () =>
              page.getByRole('button', { name: 'Recover original result', exact: true }).click(),
            );
            record = validateWorkItemRecord(record, name, bindings[name], command, itemRef);
            requireThat(record.status === 202, 'RECOVERY_UNRESOLVED');
            if (knownOperation) assert.deepEqual(record.result.operation, knownOperation.operation);
          } else {
            const pending = waitResponse(page, 'GET', 'OPERATION');
            await page
              .getByRole('button', { name: 'Recover original result', exact: true })
              .click();
            const response = await pending;
            requireThat(response.status() === 200, 'OPERATION_RECOVERY');
            workItemResumeAction(record, await response.json());
          }
          if (record.status === 412) return record;
          const pending = waitResponse(page, 'GET', 'DETAIL');
          await page.getByRole('button', { name: 'Read operation work item', exact: true }).click();
          requireThat((await pending).status() === 200, 'EFFECT_RECOVERY');
          await expect(
            page.getByRole('region', { name: 'Original request recovery', exact: true }),
          ).toHaveCount(0);
          return record;
        };

        async function runKeyboardFollowup(originalRef, originalSealed) {
          const intent = keyboardFollowupIntent(originalRef);
          const viewRoot = join(artifacts, `keyboard-${Date.now()}-${randomUUID()}`);
          await mkdir(viewRoot, { recursive: true, mode: 0o700 });
          const gaps = [];
          const retained = await Promise.all(
            commands.map((command) => load(`keyboard-${command.toLowerCase()}`)),
          );
          const priorUiPath = process.env.OPENPC_WORK_ITEM_PRIOR_UI_RESULT;
          let priorUiState;
          if (priorUiPath) {
            requireThat(
              isAbsolute(priorUiPath) &&
                resolve(priorUiPath).startsWith(artifacts + sep) &&
                /^keyboard-[0-9]+-[0-9a-f-]+\/result\.json$/u.test(
                  resolve(priorUiPath).slice(artifacts.length + 1),
                ),
              'PRIOR_UI_PATH',
            );
            priorUiState = validateWorkItemPriorUi(
              JSON.parse(await readFile(priorUiPath, 'utf8')),
              originalRef,
              retained,
              await Promise.all(
                assignedCommands.map((command) => load(`assigned-${command.toLowerCase()}`)),
              ),
            );
          }
          if (workItemFollowupResume(retained) === 'READ_KNOWN' && !priorUiState)
            gaps.push('RETAINED_TRANSIENT_UI_REQUIRES_PRIOR_EVIDENCE');
          // Necessary fixture input only, never a replacement for the actual
          // session mutation owner's scope, cardinality and current-authority checks.
          const logoutActions = await pool.query(
            `select a.assignment_id from control.assignment a
             join control.authority_envelope e using(participant_id,authority_envelope_id)
             join control.authority_role r on r.participant_id=a.participant_id and r.role_id=a.role_id
             where a.participant_id=$1 and a.principal_id=$2 and a.state='ACTIVE'
               and a.valid_during @> clock_timestamp() and e.state='ACTIVE'
               and $3=any(a.action_intent_ids) and $3=any(e.action_intent_ids) and $3=any(r.action_intent_ids)`,
            [participantId, actors.checker.principalId, 'ACT-IDENTITY_DELETE_SESSION-V1'],
          );
          if (logoutActions.rowCount === 0) gaps.push('LOGOUT_ACTION_FIXTURE_BLOCKED');
          const tabTo = async (page, target) => {
            await expect(target).toHaveCount(1);
            await expect(target).toBeVisible();
            for (let count = 0; count < 100; count++) {
              const position = await target.evaluate((element) => {
                const active = document.activeElement;
                return element === active
                  ? 'FOCUSED'
                  : active !== document.body &&
                      active &&
                      active.compareDocumentPosition(element) & Node.DOCUMENT_POSITION_PRECEDING
                    ? 'Shift+Tab'
                    : 'Tab';
              });
              if (position === 'FOCUSED') return;
              await page.keyboard.press(position);
            }
            throw new Error('WORK_ITEM_BROWSER_KEYBOARD_UNREACHABLE');
          };
          const type = async (page, label, value) => {
            const field = page.getByRole('textbox', { name: label, exact: true });
            await tabTo(page, field);
            await page.keyboard.press('Control+A');
            await page.keyboard.type(value);
            await expect(field).toHaveValue(value);
          };
          const activate = async (page, label) => {
            const button = page.getByRole('button', { name: label, exact: true });
            await expect(button).toBeEnabled();
            await tabTo(page, button);
            await page.keyboard.press('Enter');
          };
          const inspectKeyboard = async (name, selectedRef) => {
            const page = pages[name];
            const response = waitResponse(page, 'GET', 'DETAIL');
            await activate(page, `Inspect ${selectedRef}`);
            const actual = await response;
            requireThat(actual.status() === 200, 'KEYBOARD_DETAIL');
            const detail = workItemView.parse(await actual.json());
            requireThat(
              detail.kind === 'DETAIL' &&
                detail.actorKey === bindings[name].actorKey &&
                detail.workItem.workItemId === selectedRef,
              'KEYBOARD_DETAIL_BINDING',
            );
            await expect(
              page.getByRole('heading', { name: 'Work-item details', exact: true }),
            ).toBeFocused();
            requireThat(
              !('reason' in detail.workItem) && !('payloadDigest' in detail.workItem),
              'PUBLIC_FIELD_PRIVACY',
            );
            return detail;
          };
          const inspectView = async (page, stage) => {
            for (const width of [1440, 360]) {
              await page.setViewportSize({ width, height: 1000 });
              assert.deepEqual(
                (
                  await new AxeBuilder({ page })
                    .withTags(['wcag2a', 'wcag2aa', 'wcag21aa'])
                    .analyze()
                ).violations,
                [],
              );
              requireThat(
                await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
                'KEYBOARD_REFLOW',
              );
              await page.screenshot({
                path: join(viewRoot, `${stage}-${width}.png`),
                fullPage: true,
              });
            }
          };
          const currentOperation = async (record, command, selectedRef, assigned = false) => {
            const observed = await read(pages[record.actor], {
              view: 'OPERATION',
              actorKey: bindings[record.actor].actorKey,
              operationId: record.result.operation.operationId,
            });
            return validateWorkItemReboundRead(
              record,
              record.actor,
              bindings[record.actor],
              command,
              selectedRef,
              observed,
              assigned,
            );
          };
          const readEffect = async (record, known = false, assigned = false) => {
            const page = pages[record.actor];
            if (known) {
              await page.reload();
              await expect(
                page.getByRole('button', { name: 'Read operation', exact: true }),
              ).toBeEnabled();
              await type(page, 'Existing operation ID', record.result.operation.operationId);
              const pending = waitResponse(page, 'GET', 'OPERATION');
              await activate(page, 'Read operation');
              const response = await pending;
              requireThat(response.status() === 200, 'KEYBOARD_OPERATION_READ');
              validateWorkItemReboundRead(
                record,
                record.actor,
                bindings[record.actor],
                record.request.command,
                record.result.operation.resourceRef,
                await response.json(),
                assigned,
              );
            }
            await expect(
              page.getByRole('region', { name: 'Work-item operation', exact: true }),
            ).toContainText(record.result.operation.operationId);
            const response = waitResponse(page, 'GET', 'DETAIL');
            await activate(page, 'Read operation work item');
            const actual = await response;
            requireThat(actual.status() === 200, 'KEYBOARD_EFFECT_READ');
            const detail = workItemView.parse(await actual.json());
            requireThat(
              detail.kind === 'DETAIL' &&
                detail.actorKey === bindings[record.actor].actorKey &&
                detail.workItem.workItemId === record.result.operation.resourceRef,
              'KEYBOARD_EFFECT_BINDING',
            );
            await expect(
              page.getByRole('heading', { name: 'Work-item details', exact: true }),
            ).toBeFocused();
            await expect(
              page.getByRole('region', { name: 'Original request recovery', exact: true }),
            ).toHaveCount(0);
            return detail;
          };

          await maker.reload();
          await maker.setViewportSize({ width: 360, height: 1000 });
          await expect(
            maker.getByRole('button', { name: 'Create work item', exact: true }),
          ).toBeEnabled();
          let created = retained[0];
          if (!created) {
            await tabTo(maker, maker.getByRole('combobox', { name: 'Kind', exact: true }));
            await maker.keyboard.press('Home');
            await maker.keyboard.press('ArrowDown');
            await expect(maker.getByRole('combobox', { name: 'Kind', exact: true })).toHaveValue(
              intent.kind,
            );
            await type(maker, 'Resource reference', 'not-a-resource-reference');
            await type(maker, 'Reason', intent.reason);
            let posted = 0;
            const countPost = (request) => {
              if (new URL(request.url()).pathname === endpoint && request.method() === 'POST')
                posted++;
            };
            maker.on('request', countPost);
            try {
              await activate(maker, 'Create work item');
              const alert = maker
                .getByRole('region', { name: 'Work items', exact: true })
                .getByRole('alert');
              await expect(alert).toContainText('Check the kind');
              await expect(alert).toBeFocused();
              await inspectView(maker, 'input-error');
              requireThat(posted === 0, 'INVALID_INPUT_NO_SEND');
              assert.deepEqual(await snapshot(), originalSealed);
            } finally {
              maker.off('request', countPost);
            }
            await type(maker, 'Resource reference', intent.resourceRef);
            await expect(
              maker.getByLabel('Assignee reference (optional)', { exact: true }),
            ).toHaveValue('');
            created = await capture(
              'maker',
              'keyboard-create',
              'CREATE',
              () => activate(maker, 'Create work item'),
              { lose: true },
            );
            requireThat(created.status === 202, 'FOLLOWUP_CREATE');
            const pending = await maker.evaluate(
              (key) => JSON.parse(sessionStorage.getItem(key) ?? 'null'),
              storageKey,
            );
            validateNaturalWorkItemRecovery(created, pending);
            const alert = maker
              .getByRole('region', { name: 'Work items', exact: true })
              .getByRole('alert');
            await expect(alert).toBeFocused();
            await expect(alert).toContainText('response is unavailable');
            await expect(
              maker.getByRole('button', { name: 'Create work item', exact: true }),
            ).toBeDisabled();
            await inspectView(maker, 'lost-response-recovery');
            const before = await assertEffects(1, created.result.operation.resourceRef.slice(-36));
            // Only the naturally uncertain request in this same live tab may
            // use its supported exact-key recovery. No storage is injected and
            // no accepted historical transition is sent with a new request key.
            const recovered = await capture('maker', 'keyboard-create', 'CREATE', () =>
              activate(maker, 'Recover original result'),
            );
            assert.deepEqual(recovered, created);
            assert.deepEqual(
              await snapshot(created.result.operation.resourceRef.slice(-36)),
              before,
            );
          } else await currentOperation(created, 'CREATE');
          requireThat(
            created.actor === 'maker' &&
              Object.entries(intent).every(([key, value]) => created.request[key] === value),
            'FOLLOWUP_DISTINCT_INTENT',
          );
          const followupRef = created.result.operation.resourceRef,
            followupId = followupRef.slice(-36);
          requireThat(followupRef !== originalRef, 'FOLLOWUP_DISTINCT_RESOURCE');
          let detail = await readEffect(created, !!retained[0]);
          if (!retained[1]) {
            requireThat(
              detail.workItem.state === 'OPEN' && detail.workItem.revision === '1',
              'FOLLOWUP_OPEN',
            );
            await expect(
              maker.getByLabel('Replacement payload digest', { exact: true }),
            ).toBeVisible();
            await expect(
              maker.getByRole('button', { name: 'Update work item', exact: true }),
            ).toBeDisabled();
            await expect(
              maker.getByRole('button', { name: 'Claim work item', exact: true }),
            ).toBeDisabled();
            await inspectView(maker, 'open');
          }

          let updated = retained[1];
          if (!updated) {
            await refresh(checker);
            const stale = await inspectKeyboard('checker', followupRef);
            requireThat(stale.workItem.revision === '1', 'FOLLOWUP_STALE_PREREQUISITE');
            await type(
              maker,
              'Transition reason',
              'Record the keyboard follow-up diagnostic payload.',
            );
            await type(maker, 'Replacement payload digest', `sha256:${'ef'.repeat(32)}`);
            updated = await capture('maker', 'keyboard-update', 'UPDATE', () =>
              activate(maker, 'Update work item'),
            );
            requireThat(updated.status === 202, 'FOLLOWUP_UPDATE');
            const before = await assertEffects(2, followupId);
            await type(
              checker,
              'Transition reason',
              'Reject this stale keyboard follow-up revision.',
            );
            await type(checker, 'Replacement payload digest', `sha256:${'ed'.repeat(32)}`);
            const denied = await capture('checker', 'keyboard-stale-update', 'UPDATE', () =>
              activate(checker, 'Update work item'),
            );
            requireThat(
              denied.status === 412 && denied.result.code === 'PC-DATA-6007',
              'FOLLOWUP_STALE_DENIAL',
            );
            const alert = checker
              .getByRole('region', { name: 'Work items', exact: true })
              .getByRole('alert');
            await expect(alert).toBeFocused();
            await expect(alert).toContainText('selected revision is stale');
            await expect(
              checker.getByRole('button', { name: 'Recover original result', exact: true }),
            ).toBeDisabled();
            await inspectView(checker, 'stale-rejected-recovery');
            const refreshed = waitResponse(checker, 'GET', 'LIST');
            await activate(checker, 'Dismiss rejected request and refresh');
            requireThat((await refreshed).status() === 200, 'FOLLOWUP_DENIAL_REFRESH');
            await expect(
              checker.getByRole('region', { name: 'Original request recovery', exact: true }),
            ).toHaveCount(0);
            assert.deepEqual(await snapshot(followupId), before);
          } else await currentOperation(updated, 'UPDATE', followupRef);
          detail = await readEffect(updated, !!retained[1]);

          let claimed = retained[2];
          if (!claimed) {
            requireThat(
              detail.workItem.state === 'OPEN' && detail.workItem.revision === '2',
              'FOLLOWUP_CLAIM_PREREQUISITE',
            );
            await type(
              maker,
              'Transition reason',
              'Take ownership of this keyboard follow-up remediation.',
            );
            claimed = await capture('maker', 'keyboard-claim', 'CLAIM', () =>
              activate(maker, 'Claim work item'),
            );
            requireThat(claimed.status === 202, 'FOLLOWUP_CLAIM');
          } else await currentOperation(claimed, 'CLAIM', followupRef);
          detail = await readEffect(claimed, !!retained[2]);
          if (!retained[3]) {
            const claimedEffects = await assertEffects(3, followupId);
            requireThat(
              detail.workItem.state === 'CLAIMED' &&
                detail.workItem.revision === '3' &&
                claimedEffects.item[0].assignee === actors.maker.principalId &&
                claimedEffects.item[0].claimant === actors.maker.principalId &&
                claimedEffects.item[0].completer === null,
              'FOLLOWUP_CLAIMANT',
            );
            await expect(
              maker.getByRole('button', { name: 'Complete work item', exact: true }),
            ).toBeDisabled();
            await inspectView(maker, 'claimed');
          }
          let completed = retained[3];
          if (!completed) {
            await type(
              maker,
              'Transition reason',
              'Complete the keyboard follow-up metadata verification.',
            );
            completed = await capture('maker', 'keyboard-complete', 'COMPLETE', () =>
              activate(maker, 'Complete work item'),
            );
            requireThat(completed.status === 202, 'FOLLOWUP_COMPLETE');
          } else await currentOperation(completed, 'COMPLETE', followupRef);
          detail = await readEffect(completed, !!retained[3]);
          requireThat(
            detail.workItem.state === 'COMPLETED' && detail.workItem.revision === '4',
            'FOLLOWUP_COMPLETED',
          );
          await inspectView(maker, 'completed');
          const records = [created, updated, claimed, completed];
          requireThat(
            new Set(records.map((record) => record.request.requestKey)).size === 4,
            'FOLLOWUP_REQUEST_IDENTITIES',
          );
          for (const [index, record] of records.entries())
            await currentOperation(record, commands[index], followupRef);
          const sealed = await assertEffects(4, followupId);
          assert.deepEqual(
            sealed.receipts.map((receipt) => receipt.operation_id),
            records.map((record) => record.result.operation.operationId),
          );
          requireThat(
            sealed.item[0].state === 'COMPLETED' &&
              sealed.item[0].assignee === actors.maker.principalId &&
              sealed.item[0].claimant === actors.maker.principalId &&
              sealed.item[0].completer === actors.maker.principalId,
            'FOLLOWUP_COMPLETED_EFFECT',
          );
          assert.deepEqual(await snapshot(), originalSealed);

          // Assignment is a separate verification intent with exactly three
          // effects. Run before context/logout invalidates either real actor.
          const assignedIntent = assignedFollowupIntent(
            originalRef,
            bindings.checker.actor.principalRef,
          );
          const assignedFiles = assignedCommands.map(
            (command) => `assigned-${command.toLowerCase()}`,
          );
          const assignedRecords = await Promise.all(assignedFiles.map(load));
          const assignedResume = workItemAssignedResume(assignedRecords);
          const assignedKnown = assignedResume === 'READ_KNOWN';
          const assignedDenials = await Promise.all(
            ['assigned-wrong-claim', 'assigned-wrong-complete'].map(load),
          );
          requireThat(
            assignedKnown
              ? assignedDenials.every((record) => record?.status === 412)
              : assignedDenials.every((record) => record === undefined),
            'ASSIGNED_DENIAL_OUTCOME_BLOCKED',
          );
          if (assignedKnown && !priorUiState)
            gaps.push('ASSIGNED_RETAINED_CONTROLS_REQUIRE_PRIOR_EVIDENCE');
          await maker.reload();
          await expect(
            maker.getByRole('button', { name: 'Create work item', exact: true }),
          ).toBeEnabled();
          if (!assignedKnown) {
            await maker
              .getByRole('combobox', { name: 'Kind', exact: true })
              .selectOption(assignedIntent.kind);
            await type(maker, 'Resource reference', assignedIntent.resourceRef);
            await type(maker, 'Assignee reference (optional)', assignedIntent.assigneeRef);
            await type(maker, 'Reason', assignedIntent.reason);
            assignedRecords[0] = await capture('maker', assignedFiles[0], 'CREATE', () =>
              activate(maker, 'Create work item'),
            );
          }
          const assignedRef = assignedRecords[0]?.result?.operation?.resourceRef;
          requireThat(
            assignedRef && assignedRef !== originalRef && assignedRef !== followupRef,
            'ASSIGNED_DISTINCT_ITEM',
          );
          const assignedId = assignedRef.slice(-36);
          validateWorkItemRecord(
            assignedRecords[0],
            'maker',
            assignedRecords[0].result,
            'CREATE',
            assignedRef,
            true,
          );
          for (const [key, value] of Object.entries(assignedIntent))
            assert.deepEqual(
              assignedRecords[0].request[key],
              value,
              'WORK_ITEM_BROWSER_ASSIGNED_INTENT',
            );
          await currentOperation(assignedRecords[0], 'CREATE', assignedRef, true);
          let assignedDetail = await readEffect(assignedRecords[0], assignedKnown, true);

          const rejectAssignedMaker = async (command, before) => {
            await refresh(maker);
            const detail = await inspectKeyboard('maker', assignedRef);
            await type(
              maker,
              'Transition reason',
              `Reject maker ${command.toLowerCase()} of checker-assigned remediation.`,
            );
            await expect(
              maker.getByRole('button', {
                name: command === 'CLAIM' ? 'Claim work item' : 'Complete work item',
                exact: true,
              }),
            ).toBeDisabled();
            const file = `assigned-wrong-${command.toLowerCase()}`;
            const original = validateWorkItemRecord(
              {
                actor: 'maker',
                request: {
                  command,
                  actorKey: bindings.maker.actorKey,
                  requestKey: randomUUID(),
                  workItemRef: assignedRef,
                  expectedRevision: detail.workItem.revision,
                  etag: detail.etag,
                  reason: `Verify wrong-principal ${command.toLowerCase()} denial.`,
                },
              },
              'maker',
              bindings.maker,
              command,
              assignedRef,
              true,
            );
            // Persist before dispatch. Unknown outcomes can never get a new key.
            await save(file, original);
            const response = await browserPost(maker, original.request);
            const observed = { ...original, status: response.status, result: response.body };
            await save(file, observed);
            requireThat(
              response.status === 412 && response.body.code === 'PC-DATA-6007',
              'ASSIGNED_WRONG_PRINCIPAL_DENIAL',
            );
            assert.deepEqual(
              await snapshot(assignedId),
              before,
              'Wrong principal must produce no state, signed receipt or outbox effect',
            );
            await inspectView(maker, `assigned-denied-${command.toLowerCase()}`);
            return observed;
          };

          if (!assignedKnown) {
            const before = await assertEffects(1, assignedId, assignedCommands);
            requireThat(
              assignedDetail.workItem.state === 'OPEN' &&
                assignedDetail.workItem.revision === '1' &&
                assignedDetail.workItem.assigneeRef === assignedIntent.assigneeRef &&
                before.item[0].assignee === actors.checker.principalId &&
                before.item[0].claimant === null &&
                before.item[0].completer === null,
              'ASSIGNED_OPEN',
            );
            assignedDenials[0] = await rejectAssignedMaker('CLAIM', before);
            await checker.reload();
            await refresh(checker);
            const checkerDetail = await inspectKeyboard('checker', assignedRef);
            requireThat(
              checkerDetail.workItem.assigneeRef === bindings.checker.actor.principalRef,
              'ASSIGNED_CHECKER',
            );
            await type(checker, 'Transition reason', 'Claim my assigned remediation verification.');
            assignedRecords[1] = await capture('checker', assignedFiles[1], 'CLAIM', () =>
              activate(checker, 'Claim work item'),
            );
          }
          await currentOperation(assignedRecords[1], 'CLAIM', assignedRef, true);
          assignedDetail = await readEffect(assignedRecords[1], assignedKnown, true);
          if (!assignedKnown) {
            const before = await assertEffects(2, assignedId, assignedCommands);
            requireThat(
              assignedDetail.workItem.state === 'CLAIMED' &&
                assignedDetail.workItem.revision === '2' &&
                before.item[0].assignee === actors.checker.principalId &&
                before.item[0].claimant === actors.checker.principalId &&
                before.item[0].completer === null,
              'ASSIGNED_CLAIMED',
            );
            assignedDenials[1] = await rejectAssignedMaker('COMPLETE', before);
            await type(
              checker,
              'Transition reason',
              'Complete my assigned remediation verification.',
            );
            assignedRecords[2] = await capture('checker', assignedFiles[2], 'COMPLETE', () =>
              activate(checker, 'Complete work item'),
            );
          }
          await currentOperation(assignedRecords[2], 'COMPLETE', assignedRef, true);
          assignedDetail = await readEffect(assignedRecords[2], assignedKnown, true);
          requireThat(
            assignedDetail.workItem.state === 'COMPLETED' &&
              assignedDetail.workItem.revision === '3' &&
              assignedDetail.workItem.assigneeRef === assignedIntent.assigneeRef,
            'ASSIGNED_COMPLETED',
          );
          const assignedSealed = await assertEffects(3, assignedId, assignedCommands);
          requireThat(
            assignedSealed.item[0].state === 'COMPLETED' &&
              assignedSealed.item[0].assignee === actors.checker.principalId &&
              assignedSealed.item[0].claimant === actors.checker.principalId &&
              assignedSealed.item[0].completer === actors.checker.principalId,
            'ASSIGNED_COMPLETED_EFFECT',
          );
          for (const [index, record] of assignedRecords.entries()) {
            validateWorkItemRecord(
              record,
              index === 0 ? 'maker' : 'checker',
              record.result,
              assignedCommands[index],
              assignedRef,
              true,
            );
            assert.deepEqual(
              await load(assignedFiles[index]),
              record,
              'Assigned request and result must retain original bytes',
            );
          }
          for (const [index, record] of assignedDenials.entries()) {
            // A historical denial retains its original authenticated binding;
            // current authority is never substituted into its consumed request.
            validateWorkItemRecord(
              record,
              'maker',
              { ...bindings.maker, actorKey: record.request.actorKey },
              assignedCommands[index + 1],
              assignedRef,
              true,
            );
            requireThat(record.status === 412, 'ASSIGNED_RETAINED_DENIAL');
          }
          requireThat(
            new Set(
              [...assignedRecords, ...assignedDenials].map((record) => record.request.requestKey),
            ).size === 5,
            'ASSIGNED_REQUEST_IDENTITIES',
          );
          assert.deepEqual(
            assignedSealed.receipts.map((receipt) => receipt.operation_id),
            assignedRecords.map((record) => record.result.operation.operationId),
          );
          assert.deepEqual(await snapshot(), originalSealed);
          assert.deepEqual(await snapshot(followupId), sealed);
          await exec(
            compose[0],
            [...compose.slice(1), 'restart', '--no-deps', 'control-api', 'admin-web'],
            { timeout: 90000, maxBuffer: 1024 * 1024 },
          );
          await expect
            .poll(
              async () => {
                try {
                  return (await checker.request.get(`${origin}${endpoint}?view=LIST`)).status();
                } catch {
                  return 0;
                }
              },
              { timeout: 30000, intervals: [250, 500, 1000] },
            )
            .toBe(200);
          for (const [index, record] of assignedRecords.entries())
            await currentOperation(record, assignedCommands[index], assignedRef, true);
          assert.deepEqual(await readEffect(assignedRecords[2], true, true), assignedDetail);
          assert.deepEqual(
            await assertEffects(3, assignedId, assignedCommands),
            assignedSealed,
            'Assignment restart preserves original signed bytes',
          );
          assert.deepEqual(await snapshot(), originalSealed);
          assert.deepEqual(await snapshot(followupId), sealed);
          process.stdout.write(
            'OPENPC_WORK_ITEM_ASSIGNED|THREE_EFFECTS_VERIFIED|controls=' +
              (assignedKnown
                ? priorUiState
                  ? `REUSED_PRIOR_AGGREGATE_${priorUiState}`
                  : 'PRIOR_EVIDENCE_REQUIRED'
                : 'EXECUTED') +
              '\n',
          );

          const assertCleared = async (page) => {
            for (const region of [
              'Work-item details',
              'Work-item operation',
              'Original request recovery',
            ])
              await expect(page.getByRole('region', { name: region, exact: true })).toHaveCount(0);
            await expect(
              page.getByRole('list', { name: 'Work-item results', exact: true }),
            ).toHaveCount(0);
            for (const label of [
              'Resource reference',
              'Assignee reference (optional)',
              'Reason',
              'Existing operation ID',
              'Filter value',
            ])
              await expect(page.getByLabel(label, { exact: true })).toHaveValue('');
            requireThat(
              await page.evaluate((key) => sessionStorage.getItem(key) === null, storageKey),
              'CONTEXT_PENDING_CLEARED',
            );
          };
          const unavailableActors = new Set();
          const mutationResults = [];
          const mutationEffects = new Map();
          let populationResult = { state: 'BLOCKED' };
          const populationEffects = new Map();
          const preserveCompleted = async () => {
            assert.deepEqual(await snapshot(), originalSealed);
            assert.deepEqual(await snapshot(followupId), sealed);
            assert.deepEqual(await snapshot(assignedId), assignedSealed);
          };
          const restoreActor = async (name, oldSessionId) => {
            const page = pages[name];
            await authenticate(page, 'viewer', privacyDomainId, {
              participantWorkbench: false,
              expectedPrincipalId: actors[name].principalId,
            });
            await page.goto(`${origin}/operate/support?view=work-items`);
            await expect(
              page.getByRole('heading', { name: 'Work items', exact: true }),
            ).toBeVisible();
            const session = await page.evaluate(async () =>
              (await fetch('/api/v1/ui/local-session', { cache: 'no-store' })).json(),
            );
            requireThat(
              session.authenticated === true &&
                session.principalId === actors[name].principalId &&
                session.participantId === participantId &&
                session.privacyDomainId === privacyDomainId &&
                session.sessionId !== oldSessionId,
              'MUTATION_REAUTHENTICATED_OWNER',
            );
            bindings[name] = await read(page, { view: 'LIST' });
            requireThat(
              bindings[name].actor.principalRef === ref(actors[name].principalId),
              'MUTATION_REAUTHENTICATED_PRINCIPAL',
            );
          };
          const mutationReadback = async (record, transition) => {
            requireThat(
              record?.status === 202 && record.result?.kind === 'OPERATION',
              'MUTATION_OUTCOME_BLOCKED',
            );
            const observed = await read(pages[record.actor], {
              view: 'OPERATION',
              actorKey: bindings[record.actor].actorKey,
              operationId: record.result.operation.operationId,
            });
            validateWorkItemMutationRead(
              record,
              transition,
              originalRef,
              bindings[record.actor],
              observed,
            );
            const detail = await readEffect(record, true);
            requireThat(
              detail.workItem.state === 'OPEN' &&
                detail.workItem.revision === '1' &&
                detail.workItem.kind === 'REMEDIATION' &&
                detail.workItem.assigneeRef === null,
              'MUTATION_COMMITTED_EFFECT_READBACK',
            );
            const effects = await assertEffects(1, record.result.operation.resourceRef.slice(-36));
            requireThat(
              effects.item[0].state === 'OPEN' &&
                effects.item[0].assignee === null &&
                effects.item[0].claimant === null &&
                effects.item[0].completer === null &&
                effects.receipts[0].operation_id === record.result.operation.operationId,
              'MUTATION_SINGLE_CREATE_EFFECT',
            );
            mutationEffects.set(record.result.operation.resourceRef.slice(-36), effects);
            await preserveCompleted();
          };
          const invalidateMutation = async (transition) => {
            const name = transition === 'context' ? 'maker' : 'checker',
              page = pages[name];
            const file = `mutation-${transition}-create`,
              proofFile = `mutation-${transition}-result`;
            let record = await load(file);
            const priorProof = await load(proofFile);
            if (record !== undefined) {
              // This is readback only even when prior UI proof failed or is missing.
              await mutationReadback(record, transition);
              validateWorkItemMutationProof(priorProof, record, transition);
              mutationResults.push({ ...priorProof, reused: true });
              return;
            }
            requireThat(priorProof === undefined, 'MUTATION_ORPHAN_PROOF_BLOCKED');
            const beforeSession = await page.evaluate(async () =>
              (await fetch('/api/v1/ui/local-session', { cache: 'no-store' })).json(),
            );
            requireThat(
              beforeSession.authenticated === true &&
                beforeSession.principalId === actors[name].principalId &&
                beforeSession.participantId === participantId &&
                beforeSession.privacyDomainId === privacyDomainId,
              'MUTATION_INITIAL_SESSION',
            );
            const alternate =
              transition === 'context'
                ? workItemAlternateContext(beforeSession, participantId, privacyDomainId)
                : undefined;
            requireThat(
              transition !== 'context' || alternate,
              'MUTATION_ALTERNATE_CONTEXT_BLOCKED',
            );
            requireThat(
              transition !== 'logout' || logoutActions.rowCount !== 0,
              'MUTATION_LOGOUT_ACTION_BLOCKED',
            );
            const cookie = (await page.context().cookies(origin)).find(
              (entry) => entry.name === 'openpc_local_runtime_session',
            );
            requireThat(!!cookie?.value, 'MUTATION_ORIGINAL_SESSION');
            const intent = workItemMutationIntent(originalRef, transition);
            await refresh(page);
            await page
              .getByRole('combobox', { name: 'Kind', exact: true })
              .selectOption(intent.kind);
            await type(page, 'Resource reference', intent.resourceRef);
            await page
              .getByRole('textbox', { name: 'Assignee reference (optional)', exact: true })
              .fill('');
            await type(page, 'Reason', intent.reason);
            if (alternate)
              await page
                .getByRole('combobox', { name: 'Organization workspace', exact: true })
                .selectOption(alternate.privacyDomainId);
            let releaseMutation, releaseOwner, finishMutation, finishOwner;
            const mutationGate = new Promise((done) => {
              releaseMutation = done;
            });
            const ownerGate = new Promise((done) => {
              releaseOwner = done;
            });
            const mutationDone = new Promise((done) => {
              finishMutation = done;
            });
            const ownerDone = new Promise((done) => {
              finishOwner = done;
            });
            let request,
              ownerStarted = false,
              processed = false,
              transitioned = false,
              aborted = false,
              failure,
              uiCleared = false,
              readback = false;
            const failedRequest = (value) => {
              if (
                value === request &&
                /aborted|cancelled|canceled/iu.test(value.failure()?.errorText ?? '')
              )
                aborted = true;
            };
            const holdMutation = async (route) => {
              if (route.request().method() !== 'POST') return route.continue();
              try {
                requireThat(!request, 'MUTATION_DUPLICATE_SUBMISSION');
                request = route.request();
                const original = workItemCommand.parse(request.postDataJSON());
                requireThat(
                  original.command === 'CREATE' && original.actorKey === bindings[name].actorKey,
                  'MUTATION_RENDERED_CREATE',
                );
                for (const [key, value] of Object.entries(intent))
                  assert.deepEqual(original[key], value);
                record = { actor: name, request: original };
                await save(file, record);
                const actual = await route.fetch({ timeout: 15000 });
                const body = await actual.json();
                record = {
                  ...record,
                  status: actual.status(),
                  result: actual.status() === 202 ? workItemView.parse(body) : { code: body.code },
                };
                await save(file, record);
                validateWorkItemRecord(
                  record,
                  name,
                  bindings[name],
                  'CREATE',
                  record.result?.operation?.resourceRef,
                );
                requireThat(record.status === 202, 'MUTATION_COMMIT_PREREQUISITE_BLOCKED');
                processed = true;
                await mutationGate;
                try {
                  await route.fulfill({ response: actual });
                } catch (error) {
                  if (!aborted) throw error;
                }
              } catch (error) {
                failure ??= error;
                await route.abort('failed').catch(() => {});
              } finally {
                finishMutation();
              }
            };
            const ownerPath =
              transition === 'context' ? '/api/v1/ui/session/context' : '/api/v1/ui/local-session';
            const holdOwner = async (route) => {
              if (route.request().method() !== (transition === 'context' ? 'POST' : 'DELETE'))
                return route.continue();
              ownerStarted = true;
              try {
                const actual = await route.fetch({ timeout: 15000 });
                requireThat(
                  actual.status() === (transition === 'context' ? 201 : 202),
                  'MUTATION_INVALIDATION_OWNER',
                );
                transitioned = true;
                await ownerGate;
                await route.fulfill({ response: actual });
              } catch (error) {
                failure ??= error;
                await route.abort('failed').catch(() => {});
              } finally {
                finishOwner();
              }
            };
            page.on('requestfailed', failedRequest);
            await page.route(`**${endpoint}`, holdMutation);
            await page.route(`**${ownerPath}`, holdOwner);
            try {
              await activate(page, 'Create work item');
              await expect.poll(() => processed || !!failure, { timeout: 30000 }).toBe(true);
              if (failure) throw failure;
              validateNaturalWorkItemRecovery(
                record,
                await page.evaluate(
                  (key) => JSON.parse(sessionStorage.getItem(key) ?? 'null'),
                  storageKey,
                ),
              );
              await page.screenshot({
                path: join(viewRoot, `mutation-${transition}-pending.png`),
                fullPage: true,
              });
              await activate(
                page,
                transition === 'context' ? 'Verify and enter workspace' : 'Revoke local session',
              );
              await expect.poll(() => transitioned || !!failure, { timeout: 30000 }).toBe(true);
              if (failure) throw failure;
              await assertCleared(page);
              releaseMutation();
              await mutationDone;
              if (failure) throw failure;
              await page.evaluate(
                () =>
                  new Promise((done) => requestAnimationFrame(() => requestAnimationFrame(done))),
              );
              await assertCleared(page);
              await expect(
                page.getByRole('region', { name: 'Work items', exact: true }).getByRole('alert'),
              ).toHaveCount(0);
              await page.screenshot({
                path: join(viewRoot, `mutation-${transition}-cleared-before-reload.png`),
                fullPage: true,
              });
              const loaded = page.waitForEvent('load', { timeout: 30000 });
              void loaded.catch(() => {});
              releaseOwner();
              await ownerDone;
              if (failure) throw failure;
              await loaded;
              requireThat(
                await page.evaluate((key) => sessionStorage.getItem(key) === null, storageKey),
                'MUTATION_RELOAD_CLEARED',
              );
              for (const region of [
                'Work-item details',
                'Work-item operation',
                'Original request recovery',
              ])
                await expect(page.getByRole('region', { name: region, exact: true })).toHaveCount(
                  0,
                );
              for (const label of [
                'Resource reference',
                'Assignee reference (optional)',
                'Reason',
                'Existing operation ID',
              ])
                await expect(page.getByLabel(label, { exact: true })).toHaveValue('');
              const next = await page.evaluate(async () =>
                (await fetch('/api/v1/ui/local-session', { cache: 'no-store' })).json(),
              );
              requireThat(
                transition === 'context'
                  ? next.authenticated === true &&
                      next.participantId === participantId &&
                      next.privacyDomainId === alternate.privacyDomainId &&
                      next.principalId === actors[name].principalId &&
                      next.sessionId !== beforeSession.sessionId
                  : next.authenticated === false,
                'MUTATION_INVALIDATION_READBACK',
              );
              const denied = await page.request.get(
                `${origin}${endpoint}?${new URLSearchParams({ view: 'OPERATION', actorKey: record.request.actorKey, operationId: record.result.operation.operationId })}`,
              );
              requireThat(
                denied.status() === 404 && (await denied.json()).code === 'PC-AUTH-0005',
                'MUTATION_OLD_BINDING_DENIED',
              );
              if (transition === 'logout') {
                const old = await page.request.get(`${origin}/api/v1/ui/local-session`, {
                  headers: { Cookie: `${cookie.name}=${cookie.value}` },
                });
                requireThat(
                  old.status() === 200 && (await old.json()).authenticated === false,
                  'MUTATION_ORIGINAL_SESSION_REVOKED',
                );
              }
              await page.screenshot({
                path: join(viewRoot, `mutation-${transition}-cleared-after-reload.png`),
                fullPage: true,
              });
              uiCleared = true;
            } catch (error) {
              failure ??= error;
            } finally {
              releaseMutation();
              releaseOwner();
              const cleaned = await Promise.allSettled([
                page.unroute(`**${endpoint}`, holdMutation),
                page.unroute(`**${ownerPath}`, holdOwner),
                ...(request ? [mutationDone] : []),
                ...(ownerStarted ? [ownerDone] : []),
              ]);
              for (const result of cleaned)
                if (result.status === 'rejected') failure ??= result.reason;
              page.off('requestfailed', failedRequest);
            }
            try {
              await restoreActor(name, beforeSession.sessionId);
            } catch (error) {
              unavailableActors.add(name);
              failure ??= error;
            }
            try {
              if (!unavailableActors.has(name)) {
                await mutationReadback(record, transition);
                assert.deepEqual(
                  await load(file),
                  record,
                  'Mutation invalidation must preserve original request and result bytes',
                );
                readback = true;
              }
              await preserveCompleted();
            } catch (error) {
              failure ??= error;
            }
            const proof = {
              transition,
              state: record?.status !== 202 ? 'BLOCKED' : failure ? 'FAIL' : 'PASS',
              requestKey: record?.request?.requestKey,
              operationId: record?.result?.operation?.operationId,
              workItemRef: record?.result?.operation?.resourceRef,
              observedStatus: record?.status ?? 'UNKNOWN',
              effects: readback ? 1 : null,
              uiCleared,
              reauthenticatedReadback: readback,
              visualInspection: 'PENDING_INTEGRATOR',
              artifacts: viewRoot,
            };
            await save(proofFile, proof);
            mutationResults.push(proof);
            if (failure) throw failure;
            validateWorkItemMutationProof(proof, record, transition);
          };
          // Hold real replies at the browser transport boundary. No response,
          // authenticated state, DOM event, or context authority is fabricated.
          const invalidateRead = async (name, transition, action) => {
            const page = pages[name];
            await page
              .getByRole('combobox', { name: /^Filter field/u })
              .selectOption('resourceRef');
            await page
              .getByRole('textbox', { name: 'Filter value', exact: true })
              .fill(originalRef);
            await page.getByRole('combobox', { name: /^Sort/u }).selectOption('updatedAt');
            await refresh(page);
            await inspectKeyboard(name, followupRef);
            await type(page, 'Reason', 'This protected follow-up draft must be cleared.');
            let releaseRead, releaseOwner, finishRead, finishOwner;
            const readGate = new Promise((done) => {
              releaseRead = done;
            });
            const ownerGate = new Promise((done) => {
              releaseOwner = done;
            });
            const readDone = new Promise((done) => {
              finishRead = done;
            });
            const ownerDone = new Promise((done) => {
              finishOwner = done;
            });
            let heldRead = false,
              committed = false,
              ownerStarted = false,
              failure,
              requestAborted = false;
            let readRequest;
            const failedRequest = (request) => {
              if (
                request === readRequest &&
                /aborted|cancelled|canceled/iu.test(request.failure()?.errorText ?? '')
              )
                requestAborted = true;
            };
            const holdRead = async (route) => {
              readRequest = route.request();
              try {
                const actual = await route.fetch({ timeout: 15000 });
                requireThat(actual.status() === 200, 'CONTEXT_OLD_DETAIL');
                heldRead = true;
                await readGate;
                try {
                  await route.fulfill({ response: actual });
                } catch (error) {
                  if (!requestAborted) throw error;
                }
              } catch (error) {
                failure ??= error;
                await route.abort('failed').catch(() => {});
              } finally {
                finishRead();
              }
            };
            const ownerPath =
              transition === 'context' ? '/api/v1/ui/session/context' : '/api/v1/ui/local-session';
            const holdOwner = async (route) => {
              if (route.request().method() !== (transition === 'context' ? 'POST' : 'DELETE'))
                return route.continue();
              ownerStarted = true;
              try {
                const actual = await route.fetch({ timeout: 15000 });
                requireThat(
                  actual.status() === (transition === 'context' ? 201 : 202),
                  'CONTEXT_OWNER_TRANSITION',
                );
                committed = true;
                await ownerGate;
                await route.fulfill({ response: actual });
              } catch (error) {
                failure ??= error;
                await route.abort('failed').catch(() => {});
              } finally {
                finishOwner();
              }
            };
            page.on('requestfailed', failedRequest);
            await page.route(`**${endpoint}?*view=DETAIL*`, holdRead);
            await page.route(`**${ownerPath}`, holdOwner);
            try {
              await activate(page, `Inspect ${followupRef}`);
              await expect.poll(() => heldRead || !!failure, { timeout: 30000 }).toBe(true);
              if (failure) throw failure;
              await action();
              await expect.poll(() => committed || !!failure, { timeout: 30000 }).toBe(true);
              if (failure) throw failure;
              await assertCleared(page);
              releaseRead();
              await readDone;
              if (failure) throw failure;
              await page.evaluate(
                () =>
                  new Promise((done) => requestAnimationFrame(() => requestAnimationFrame(done))),
              );
              await assertCleared(page);
              const loaded = page.waitForEvent('load', { timeout: 30000 });
              void loaded.catch(() => {});
              releaseOwner();
              await ownerDone;
              if (failure) throw failure;
              await loaded;
              requireThat(
                await page.evaluate((key) => sessionStorage.getItem(key) === null, storageKey),
                'CONTEXT_RELOAD_CLEARED',
              );
              await inspectView(page, `${transition}-cleared`);
            } catch (error) {
              failure ??= error;
            } finally {
              releaseRead();
              releaseOwner();
              const cleaned = await Promise.allSettled([
                page.unroute(`**${endpoint}?*view=DETAIL*`, holdRead),
                page.unroute(`**${ownerPath}`, holdOwner),
                ...(readRequest ? [readDone] : []),
                ...(ownerStarted ? [ownerDone] : []),
              ]);
              for (const result of cleaned)
                if (result.status === 'rejected') failure ??= result.reason;
              page.off('requestfailed', failedRequest);
            }
            if (failure) throw failure;
          };
          const runPopulation = async () => {
            requireThat(
              mutationResults.length === 2 &&
                mutationResults.every((result) => result.state === 'PASS') &&
                unavailableActors.size === 0,
              'POPULATION_AUTHENTICATED_PREREQUISITE_BLOCKED',
            );
            const rows = async (field, value, sort = 'updatedAt') => {
              const columns = {
                state: 'state',
                kind: 'kind',
                resourceRef: 'resource_ref',
                assigneeRef: "'urn:openpc:resource:'||assignee_principal_id::text",
              };
              requireThat(
                Object.hasOwn(columns, field) && ['updatedAt', '-updatedAt'].includes(sort),
                'POPULATION_QUERY',
              );
              const direction = sort === 'updatedAt' ? 'asc' : 'desc';
              return (
                await pool.query(
                  `select work_item_id::text id,kind,state,row_version::text revision,resource_ref as "resourceRef",assignee_principal_id::text assignee
                 from control.work_item where participant_id=$1 and privacy_domain_id=$2 and ${columns[field]}=$3
                 order by updated_at ${direction},work_item_id ${direction}`,
                  [participantId, privacyDomainId, value],
                )
              ).rows;
            };
            let plan = await load('pagination-intents');
            if (!plan) {
              const initial = await rows('resourceRef', originalRef);
              const initialRefs = initial.map((row) => ref(row.id));
              const initialScopedCount = (
                await pool.query(
                  'select count(*)::text total from control.work_item where participant_id=$1 and privacy_domain_id=$2',
                  [participantId, privacyDomainId],
                )
              ).rows[0].total;
              const initialSnapshots = {};
              for (const row of initial)
                initialSnapshots[row.id] = JSON.stringify(await snapshot(row.id));
              // Publish exact identities and independent intents once, before any CREATE.
              plan = {
                originalRef,
                initialScopedCount,
                initialRefs,
                initialSnapshots,
                effects: {},
                intents: workItemPopulationIntents(originalRef, initialRefs),
              };
              // Lost plan data must not turn retained effects into replacement intents.
              for (let index = 0; index < 26; index++)
                requireThat(
                  (await load(`pagination-create-${index}`)) === undefined,
                  'POPULATION_ORPHAN_CAPTURE_BLOCKED',
                );
              await save('pagination-intents', plan);
            }
            requireThat(plan.originalRef === originalRef, 'POPULATION_ORIGINAL_RESOURCE');
            requireThat(
              typeof plan.initialScopedCount === 'string' &&
                /^(0|[1-9][0-9]*)$/u.test(plan.initialScopedCount) &&
                BigInt(plan.initialScopedCount) >= BigInt(plan.initialRefs.length),
              'POPULATION_INITIAL_COUNT',
            );
            assert.deepEqual(
              plan.intents,
              workItemPopulationIntents(originalRef, plan.initialRefs),
            );
            assert.deepEqual(
              Object.keys(plan.initialSnapshots).sort(),
              plan.initialRefs.map((value) => value.slice(-36)).sort(),
            );
            const files = plan.intents.map((_, index) => `pagination-create-${index}`);
            const captured = await Promise.all(files.map(load));
            workItemPopulationResume(captured);
            requireThat(
              plan.effects &&
                typeof plan.effects === 'object' &&
                !Array.isArray(plan.effects) &&
                Object.keys(plan.effects).every((id) =>
                  captured.some((record) => record?.result?.operation?.resourceRef === ref(id)),
                ),
              'POPULATION_EFFECT_BINDINGS',
            );
            let phase = 'RETAINED_READBACK';
            try {
              for (const reference of plan.initialRefs)
                requireThat(
                  JSON.stringify(await snapshot(reference.slice(-36))) ===
                    plan.initialSnapshots[reference.slice(-36)],
                  'POPULATION_INITIAL_EFFECT_DRIFT',
                );
              const knownRefs = [];
              for (const [index, record] of captured.entries()) {
                if (!record) continue;
                const observed = await read(maker, {
                  view: 'OPERATION',
                  actorKey: bindings.maker.actorKey,
                  operationId: record.result.operation.operationId,
                });
                validateWorkItemPopulationRead(
                  record,
                  plan.intents[index],
                  bindings.maker,
                  observed,
                );
                knownRefs.push(record.result.operation.resourceRef);
              }
              requireThat(
                new Set([...plan.initialRefs, ...knownRefs]).size ===
                  plan.initialRefs.length + knownRefs.length,
                'POPULATION_DUPLICATE_IDENTITY',
              );
              assert.deepEqual(
                (await rows('resourceRef', originalRef)).map((row) => ref(row.id)).sort(),
                [...plan.initialRefs, ...knownRefs].sort(),
              );
              requireThat(!plan.firstFailure, 'POPULATION_FIRST_FAILURE_BLOCKED');
              await maker.reload();
              await expect(
                maker.getByRole('button', { name: 'Create work item', exact: true }),
              ).toBeEnabled();
              for (const [index, intent] of plan.intents.entries()) {
                phase = `CREATE_${index}`;
                const known = captured[index] !== undefined;
                if (!captured[index]) {
                  await maker
                    .getByRole('combobox', { name: 'Kind', exact: true })
                    .selectOption(intent.kind);
                  await type(maker, 'Resource reference', intent.resourceRef);
                  await maker
                    .getByRole('textbox', { name: 'Assignee reference (optional)', exact: true })
                    .fill('');
                  await type(maker, 'Reason', intent.reason);
                  // Existing capture saves the exact request before route.fetch.
                  captured[index] = await capture('maker', files[index], 'CREATE', () =>
                    activate(maker, 'Create work item'),
                  );
                }
                const record = captured[index];
                requireThat(
                  record?.status === 202 && record.result?.kind === 'OPERATION',
                  'POPULATION_CREATE_OUTCOME_BLOCKED',
                );
                const observed = await read(maker, {
                  view: 'OPERATION',
                  actorKey: bindings.maker.actorKey,
                  operationId: record.result.operation.operationId,
                });
                validateWorkItemPopulationRead(record, intent, bindings.maker, observed);
                const detail = await readEffect(record, known);
                requireThat(
                  detail.workItem.state === 'OPEN' &&
                    detail.workItem.revision === '1' &&
                    detail.workItem.kind === 'REMEDIATION' &&
                    detail.workItem.assigneeRef === null &&
                    detail.workItem.resourceRef === originalRef,
                  'POPULATION_CREATE_EFFECT',
                );
                const effects = await assertEffects(
                  1,
                  record.result.operation.resourceRef.slice(-36),
                );
                requireThat(
                  effects.item[0].state === 'OPEN' &&
                    effects.item[0].assignee === null &&
                    effects.item[0].claimant === null &&
                    effects.item[0].completer === null &&
                    effects.receipts[0].operation_id === record.result.operation.operationId,
                  'POPULATION_SIGNED_CREATE',
                );
                populationEffects.set(record.result.operation.resourceRef.slice(-36), effects);
                const effectId = record.result.operation.resourceRef.slice(-36);
                if (Object.hasOwn(plan.effects, effectId))
                  requireThat(
                    plan.effects[effectId] === JSON.stringify(effects),
                    'POPULATION_RETAINED_SIGNED_BYTES',
                  );
                else {
                  plan.effects[effectId] = JSON.stringify(effects);
                  await save('pagination-intents', plan);
                }
              }
              const allRefs = [
                ...plan.initialRefs,
                ...captured.map((record) => record.result.operation.resourceRef),
              ];
              requireThat(
                allRefs.length >= 26 &&
                  new Set(allRefs).size === allRefs.length &&
                  new Set(captured.map((record) => record.request.requestKey)).size ===
                    captured.length,
                'POPULATION_CARDINALITY',
              );
              const unchanged = async () => {
                await preserveCompleted();
                for (const [id, effects] of mutationEffects)
                  assert.deepEqual(await snapshot(id), effects);
                for (const reference of plan.initialRefs)
                  requireThat(
                    JSON.stringify(await snapshot(reference.slice(-36))) ===
                      plan.initialSnapshots[reference.slice(-36)],
                    'POPULATION_INITIAL_EFFECT_DRIFT',
                  );
                for (const [id, effects] of populationEffects)
                  assert.deepEqual(await snapshot(id), effects);
                for (const [index, record] of captured.entries())
                  assert.deepEqual(await load(files[index]), record);
              };
              const walk = async (field, value, sort, visual = false) => {
                const expected = await rows(field, value, sort);
                await maker.getByRole('combobox', { name: /^Filter field/u }).selectOption(field);
                await maker.getByRole('textbox', { name: 'Filter value', exact: true }).fill(value);
                await maker.getByRole('combobox', { name: /^Sort/u }).selectOption(sort);
                let pending = waitResponse(maker, 'GET', 'LIST');
                await activate(maker, 'Refresh work items');
                let reply = await pending,
                  first,
                  snapshotRevision;
                const seen = [],
                  cursors = new Set();
                for (let pageIndex = 0; ; pageIndex++) {
                  requireThat(
                    pageIndex <= Math.ceil(expected.length / 25),
                    'POPULATION_CURSOR_LOOP',
                  );
                  requireThat(
                    reply.status() === 200 && reply.headers()['cache-control'] === 'no-store',
                    'POPULATION_LIST_RESPONSE',
                  );
                  const view = workItemView.parse(await reply.json());
                  requireThat(
                    view.kind === 'LIST' && view.actorKey === bindings.maker.actorKey,
                    'POPULATION_LIST_BINDING',
                  );
                  assert.deepEqual(view.actor, bindings.maker.actor);
                  first ??= view;
                  snapshotRevision ??= view.page.snapshotRevision;
                  requireThat(
                    view.page.snapshotRevision === snapshotRevision &&
                      view.page.total === String(expected.length) &&
                      view.page.completeness === 'COMPLETE' &&
                      view.page.authorizedEmpty === (expected.length === 0),
                    'POPULATION_COUNT_COMPLETENESS',
                  );
                  const slice = expected.slice(seen.length, seen.length + 25);
                  assert.deepEqual(
                    view.page.items.map((item) => item.workItemId),
                    slice.map((row) => ref(row.id)),
                  );
                  const list = maker.getByRole('list', { name: 'Work-item results', exact: true });
                  if (slice.length) {
                    await expect(list.getByRole('listitem')).toHaveCount(slice.length);
                    await expect(list.getByRole('button')).toHaveText(
                      slice.map((row) => `Inspect ${ref(row.id)}`),
                    );
                    for (const [index, row] of slice.entries()) {
                      const item = view.page.items[index];
                      requireThat(
                        item.participantId === `urn:openpc:participant:${participantId}` &&
                          item.state === row.state &&
                          item.kind === row.kind &&
                          item.revision === row.revision &&
                          item.resourceRef === row.resourceRef &&
                          item.assigneeRef === (row.assignee ? ref(row.assignee) : null),
                        'POPULATION_PUBLIC_ROW',
                      );
                      await expect(list.getByRole('listitem').nth(index)).toContainText(
                        `${row.kind} · ${row.state}`,
                      );
                    }
                    const before = await snapshot(slice[0].id);
                    const detail = await inspectKeyboard('maker', ref(slice[0].id));
                    assert.deepEqual(detail.workItem, view.page.items[0]);
                    assert.deepEqual(
                      await snapshot(slice[0].id),
                      before,
                      'Inspect does not claim, update or complete',
                    );
                  } else {
                    await expect(list).toHaveCount(0);
                    await expect(
                      maker.getByText('No authorized work items match this filter.', {
                        exact: true,
                      }),
                    ).toHaveCount(2);
                  }
                  await expect(
                    maker.getByText(`${expected.length} matching work items`, { exact: false }),
                  ).toContainText('Completeness: COMPLETE');
                  if (visual && pageIndex < 2)
                    await inspectView(maker, `pagination-page-${pageIndex + 1}`);
                  seen.push(...view.page.items.map((item) => item.workItemId));
                  const next = maker.getByRole('button', { name: 'Next page', exact: true });
                  if (view.page.nextCursor === null) {
                    await expect(next).toBeDisabled();
                    break;
                  }
                  requireThat(!cursors.has(view.page.nextCursor), 'POPULATION_REPEATED_CURSOR');
                  cursors.add(view.page.nextCursor);
                  pending = waitResponse(maker, 'GET', 'LIST');
                  await activate(maker, 'Next page');
                  reply = await pending;
                  const query = new URL(reply.url()).searchParams;
                  requireThat(
                    query.get('cursor') === view.page.nextCursor &&
                      query.get('filter') === `${field}:eq:${value}` &&
                      query.get('sort') === sort &&
                      query.get('limit') === '25',
                    'POPULATION_CURSOR_QUERY',
                  );
                }
                assert.deepEqual(
                  seen,
                  expected.map((row) => ref(row.id)),
                );
                requireThat(new Set(seen).size === expected.length, 'POPULATION_NO_DUPLICATES');
                return first;
              };
              phase = 'LIST_FILTERS';
              const first = await walk('resourceRef', originalRef, 'updatedAt', true);
              requireThat(
                first.page.nextCursor !== null &&
                  first.page.items.length === 25 &&
                  first.page.total === String(allRefs.length),
                'POPULATION_BOUNDARY',
              );
              await walk('resourceRef', originalRef, '-updatedAt');
              for (const state of ['OPEN', 'COMPLETED']) await walk('state', state, 'updatedAt');
              await walk('kind', 'REMEDIATION', '-updatedAt');
              for (const actor of actorNames)
                await walk('assigneeRef', ref(actors[actor].principalId), 'updatedAt');
              // A typed existing actor reference is a valid resource filter. Select
              // only an actually empty value; do not seed a fictitious resource.
              const empty = [ref(actors.checker.principalId), ref(actors.maker.principalId)];
              let emptyRef;
              for (const candidate of empty)
                if ((await rows('resourceRef', candidate)).length === 0) {
                  emptyRef = candidate;
                  break;
                }
              requireThat(emptyRef, 'POPULATION_EMPTY_FILTER_FIXTURE_BLOCKED');
              await walk('resourceRef', emptyRef, 'updatedAt');
              await unchanged();
              phase = 'CURSOR_DENIALS';
              const query = {
                view: 'LIST',
                limit: '25',
                filter: `resourceRef:eq:${originalRef}`,
                sort: 'updatedAt',
                cursor: first.page.nextCursor,
              };
              const tampered = `${query.cursor.slice(0, -1)}${query.cursor.endsWith('A') ? 'B' : 'A'}`;
              for (const [page, parameters] of [
                [maker, { ...query, cursor: tampered }],
                [maker, { ...query, sort: '-updatedAt' }],
                [maker, { ...query, filter: 'state:eq:OPEN' }],
                [checker, query],
              ]) {
                const denied = await page.request.get(
                  `${origin}${endpoint}?${new URLSearchParams(parameters)}`,
                );
                requireThat(
                  denied.status() === 400 && (await denied.json()).code === 'PC-DATA-6004',
                  'POPULATION_CURSOR_DENIAL',
                );
              }
              const foreign = await maker.request.get(
                `${origin}${endpoint}?${new URLSearchParams({ view: 'DETAIL', actorKey: bindings.checker.actorKey, workItemRef: allRefs[0] })}`,
              );
              requireThat(
                foreign.status() === 404 && (await foreign.json()).code === 'PC-AUTH-0005',
                'POPULATION_FOREIGN_BINDING_DENIAL',
              );
              await unchanged();
              phase = 'RESTART';
              await exec(
                compose[0],
                [...compose.slice(1), 'restart', '--no-deps', 'control-api', 'admin-web'],
                { timeout: 90000, maxBuffer: 1024 * 1024 },
              );
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
              for (const [index, record] of captured.entries()) {
                const observed = await read(maker, {
                  view: 'OPERATION',
                  actorKey: bindings.maker.actorKey,
                  operationId: record.result.operation.operationId,
                });
                validateWorkItemPopulationRead(
                  record,
                  plan.intents[index],
                  bindings.maker,
                  observed,
                );
              }
              await unchanged();
              await maker.reload();
              await walk('resourceRef', originalRef, 'updatedAt');
              populationResult = {
                state: 'PASS',
                initialScopedCount: plan.initialScopedCount,
                initialMatchingCount: plan.initialRefs.length,
                addedEffects: captured.length,
                total: allRefs.length,
                visualInspection: 'PENDING_INTEGRATOR',
              };
            } catch (error) {
              plan.firstFailure ??= {
                phase,
                state: /BLOCKED/u.test(error.message) ? 'BLOCKED' : 'FAIL',
              };
              await save('pagination-intents', plan);
              throw error;
            }
          };
          let firstFailure;
          for (const transition of ['context', 'logout']) {
            try {
              await invalidateMutation(transition);
            } catch (error) {
              firstFailure ??= error;
              if (!mutationResults.some((result) => result.transition === transition))
                mutationResults.push({
                  transition,
                  state: /BLOCKED/u.test(error.message) ? 'BLOCKED' : 'FAIL',
                  effects: null,
                });
            }
          }
          try {
            await runPopulation();
          } catch (error) {
            firstFailure ??= error;
            populationResult = { state: /BLOCKED/u.test(error.message) ? 'BLOCKED' : 'FAIL' };
          }
          let session, alternate;
          try {
            requireThat(!unavailableActors.has('maker'), 'MUTATION_MAKER_REAUTH_BLOCKED');
            session = await maker.evaluate(async () =>
              (await fetch('/api/v1/ui/local-session', { cache: 'no-store' })).json(),
            );
            alternate = workItemAlternateContext(session, participantId, privacyDomainId);
          } catch (error) {
            firstFailure ??= error;
          }
          if (!alternate) gaps.push('ALTERNATE_ADVERTISED_CONTEXT_BLOCKED');
          else {
            try {
              requireThat(!unavailableActors.has('maker'), 'MUTATION_MAKER_REAUTH_BLOCKED');
              const selector = maker.getByRole('combobox', {
                name: 'Organization workspace',
                exact: true,
              });
              await selector.selectOption(alternate.privacyDomainId);
              await invalidateRead('maker', 'context', () =>
                activate(maker, 'Verify and enter workspace'),
              );
              const next = await maker.evaluate(async () =>
                (await fetch('/api/v1/ui/local-session', { cache: 'no-store' })).json(),
              );
              requireThat(
                next.authenticated === true &&
                  next.privacyDomainId === alternate.privacyDomainId &&
                  next.participantId === participantId &&
                  next.principalId === actors.maker.principalId &&
                  next.sessionId !== session.sessionId,
                'ALTERNATE_CONTEXT_READBACK',
              );
              const oldRead = await maker.request.get(
                `${origin}${endpoint}?${new URLSearchParams({ view: 'DETAIL', actorKey: bindings.maker.actorKey, workItemRef: followupRef })}`,
              );
              requireThat(
                oldRead.status() === 404 && (await oldRead.json()).code === 'PC-AUTH-0005',
                'OLD_CONTEXT_READ_DENIAL',
              );
            } catch (error) {
              firstFailure ??= error;
            }
          }
          // Independent checker session: a missing alternate context or failed
          // maker context check must not skip supported logout invalidation.
          if (logoutActions.rowCount !== 0) {
            try {
              requireThat(!unavailableActors.has('checker'), 'MUTATION_CHECKER_REAUTH_BLOCKED');
              const cookie = (await checker.context().cookies(origin)).find(
                (entry) => entry.name === 'openpc_local_runtime_session',
              );
              requireThat(!!cookie?.value, 'LOGOUT_ORIGINAL_SESSION');
              await invalidateRead('checker', 'logout', () =>
                activate(checker, 'Revoke local session'),
              );
              const next = await checker.evaluate(async () =>
                (await fetch('/api/v1/ui/local-session', { cache: 'no-store' })).json(),
              );
              requireThat(next.authenticated === false, 'LOGOUT_READBACK');
              // Cookie clearing alone is insufficient: the old real session
              // must also fail authoritative BFF/Identity validation.
              const headers = { Cookie: `${cookie.name}=${cookie.value}` };
              const old = await checker.request.get(`${origin}/api/v1/ui/local-session`, {
                headers,
              });
              requireThat(
                old.status() === 200 && (await old.json()).authenticated === false,
                'LOGOUT_ORIGINAL_SESSION_REVOKED',
              );
              const denied = await checker.request.get(`${origin}${endpoint}?view=LIST`, {
                headers,
              });
              requireThat(
                denied.status() === 404 && (await denied.json()).code === 'PC-AUTH-0005',
                'LOGOUT_WORK_ITEM_DENIAL',
              );
            } catch (error) {
              firstFailure ??= error;
            }
          }
          try {
            assert.deepEqual(await snapshot(followupId), sealed);
            assert.deepEqual(await snapshot(), originalSealed);
            assert.deepEqual(await snapshot(assignedId), assignedSealed);
            for (const [id, effects] of mutationEffects)
              assert.deepEqual(await snapshot(id), effects);
            for (const [id, effects] of populationEffects)
              assert.deepEqual(await snapshot(id), effects);
            if (mutationResults.every((result) => result.state === 'PASS')) {
              requireThat(
                mutationEffects.size === 2 &&
                  new Set(mutationResults.map((result) => result.requestKey)).size === 2,
                'MUTATION_DISTINCT_EFFECTS',
              );
            }
          } catch (error) {
            firstFailure ??= error;
          }
          const state = firstFailure ? 'FAIL' : gaps.length ? 'BLOCKED' : 'PASS';
          await writeFile(
            join(viewRoot, 'result.json'),
            JSON.stringify({
              state,
              originalWorkItemRef: originalRef,
              followupWorkItemRef: followupRef,
              originalEffects: 4,
              followupEffects: 4,
              assignedWorkItemRef: assignedRef,
              assignedEffects: 3,
              ...(priorUiPath
                ? { priorUiResult: priorUiPath, priorAggregateState: priorUiState }
                : {}),
              assignedOperations: assignedRecords.map(
                (record) => record.result.operation.operationId,
              ),
              operations: records.map((record) => record.result.operation.operationId),
              mutationInvalidation: mutationResults,
              verifiedMutationEffects: mutationEffects.size,
              populatedPagination: populationResult,
              gaps,
              visualInspection: 'PENDING_INTEGRATOR',
              remainingCoverage: [
                ...(mutationResults.length !== 2 ||
                mutationResults.some((result) => result.state !== 'PASS')
                  ? ['IN_FLIGHT_MUTATION_INVALIDATION']
                  : []),
                'OTHER_REQUIRED_KINDS',
                ...(populationResult.state === 'PASS' ? [] : ['POPULATED_PAGINATION']),
              ],
            }),
            { mode: 0o600, flag: 'wx' },
          );
          process.stdout.write(
            `OPENPC_WORK_ITEM_KEYBOARD|${state}|original-effects=4|followup-effects=4|assigned-effects=3|read-and-mutation-invalidation|visual-inspection=PENDING${gaps.map((gap) => `|${gap}`).join('')}\n`,
          );
          if (firstFailure) throw firstFailure;
          requireThat(gaps.length === 0, 'FOLLOWUP_REQUIRED_COVERAGE_BLOCKED');
        }

        let created = await load('create');
        const freshCreate = !created;
        if (!created) {
          await maker
            .getByRole('combobox', { name: 'Kind', exact: true })
            .selectOption('REMEDIATION');
          await maker
            .getByLabel('Resource reference', { exact: true })
            .fill(ref(actors.maker.principalId));
          await maker
            .getByLabel('Reason', { exact: true })
            .fill('Investigate the isolated work-item acceptance case.');
          created = await capture(
            'maker',
            'create',
            'CREATE',
            () => maker.getByRole('button', { name: 'Create work item', exact: true }).click(),
            { lose: true },
          );
          await expect(
            maker.getByRole('region', { name: 'Work items', exact: true }).getByRole('alert'),
          ).toContainText('response is unavailable');
        }
        created = await recover('maker', 'create', 'CREATE', undefined, freshCreate);
        requireThat(
          created.request.kind === 'REMEDIATION' &&
            created.request.assigneeRef === null &&
            created.request.resourceRef === ref(actors.maker.principalId),
          'CREATE_INTENT',
        );
        requireThat(created.status === 202, 'CREATE_REQUIRED');
        const itemRef = created.result.operation.resourceRef,
          itemId = itemRef.slice(-36);
        const snapshot = async (selectedItemId = itemId) => {
          const values = [participantId, privacyDomainId, selectedItemId];
          const item = (
            await pool.query(
              `select state,row_version::text revision,assignee_principal_id::text assignee,claimed_by_principal_id::text claimant,completed_by_principal_id::text completer from control.work_item where participant_id=$1 and privacy_domain_id=$2 and work_item_id=$3`,
              values,
            )
          ).rows;
          const receipts = (
            await pool.query(
              `select a.*, k.public_key_spki_der from control.audit_occurrence a join control.business_signing_key k using(participant_id,privacy_domain_id,signer_id) where a.participant_id=$1 and a.privacy_domain_id=$2 and a.aggregate_type='work-item' and a.aggregate_id=$3 order by a.after_revision`,
              values,
            )
          ).rows;
          const outbox = (
            await pool.query(
              `select e.event_id,e.receipt_id,e.correlation_id,e.proof_kind,e.sequence_namespace,e.business_sequence,e.payload_cbor from control.outbox_event e where e.participant_id=$1 and e.privacy_domain_id=$2 and e.aggregate_type='work-item' and e.aggregate_id=$3 order by e.receipt_id`,
              values,
            )
          ).rows;
          return { item, receipts, outbox };
        };
        const assertEffects = async (count, selectedItemId = itemId, sequence = commands) => {
          const actual = await snapshot(selectedItemId);
          requireThat(
            actual.item.length === 1 &&
              actual.receipts.length === count &&
              actual.outbox.length === count &&
              actual.item[0].revision === String(count),
            'SIGNED_EFFECT_CARDINALITY',
          );
          for (const [index, row] of actual.receipts.entries()) {
            requireThat(
              kernel.verifyReceiptCose(row.public_key_spki_der, row.receipt_cbor, row.cose_sign1),
              'RECEIPT_SIGNATURE',
            );
            const receipt = kernel.decodeAdmittedReceipt(row.receipt_cbor);
            requireThat(
              receipt.participantId === participantId &&
                receipt.privacyDomainId === privacyDomainId &&
                receipt.aggregateId === selectedItemId &&
                receipt.aggregateType === 'work-item' &&
                receipt.before.revision === BigInt(index) &&
                receipt.after.revision === BigInt(index + 1),
              'RECEIPT_STATE',
            );
            requireThat(
              row.action_intent_id === workItemActions[sequence[index]],
              'RECEIPT_ACTION',
            );
            requireThat(
              receipt.operationId === row.operation_id &&
                receipt.actionIntentId === row.action_intent_id,
              'RECEIPT_OPERATION',
            );
            assert.deepEqual(hash(row.before_state_preimage), row.before_state_digest);
            assert.deepEqual(hash(row.after_state_preimage), row.after_state_digest);
            assert.deepEqual(receipt.before.stateDigest, row.before_state_digest);
            assert.deepEqual(receipt.after.stateDigest, row.after_state_digest);
            assert.deepEqual(hash(row.receipt_cbor), row.receipt_digest);
            const bound = (
              await pool.query(
                `select a.payload_cbor,a.payload_digest from control.receipt_signing_attempt a join control.outbox_event e on e.participant_id=a.participant_id and e.privacy_domain_id=a.privacy_domain_id and e.receipt_id=a.attempt_id where a.participant_id=$1 and a.privacy_domain_id=$2 and a.operation_id=$3 and a.attempt_id=$4`,
                [participantId, privacyDomainId, row.operation_id, row.receipt_id],
              )
            ).rows;
            requireThat(bound.length === 1, 'ATTEMPT_OUTBOX_BINDING');
            assert.deepEqual(bound[0].payload_cbor, row.receipt_cbor);
            assert.deepEqual(bound[0].payload_digest, row.receipt_digest);
            const event = actual.outbox.find((entry) => entry.receipt_id === row.receipt_id);
            requireThat(
              event &&
                receipt.outboxEvents.length === 1 &&
                event.event_id === receipt.outboxEvents[0].eventId &&
                event.correlation_id === row.operation_id &&
                event.proof_kind === 'BUSINESS_RECEIPT_REFERENCE' &&
                event.sequence_namespace === 'CONTROL_BUSINESS_TRANSITION_V1' &&
                BigInt(event.business_sequence) === receipt.outboxEvents[0].aggregateSequence,
              'OUTBOX_RECEIPT_REFERENCE',
            );
            assert.deepEqual(hash(event.payload_cbor), receipt.outboxEvents[0].payloadDigest);
          }
          return actual;
        };

        // A completed retained acceptance is a read-only prerequisite for the
        // follow-up. Do not redispatch its original mutations or rewrite its
        // denials merely because session/context tests rotate browser authority.
        const previous = await load('result');
        if (previous) {
          requireThat(
            previous.state === 'COMPLETED' &&
              previous.effects === 4 &&
              previous.workItemRef === itemRef,
            'RETAINED_BASELINE_REQUIRED',
          );
          const retainedClaims = await Promise.all(actorNames.map((name) => load(`claim-${name}`)));
          const originalWinner = workItemClaimWinner(retainedClaims);
          const originals = [
            created,
            await load('update'),
            retainedClaims.find((record) => record.status === 202),
            await load('complete'),
          ];
          requireThat(
            originals.every((record) => record?.status === 202),
            'RETAINED_BASELINE_REQUIRED',
          );
          for (const [index, record] of originals.entries()) {
            const observed = await read(pages[record.actor], {
              view: 'OPERATION',
              actorKey: bindings[record.actor].actorKey,
              operationId: record.result.operation.operationId,
            });
            validateWorkItemReboundRead(
              record,
              record.actor,
              bindings[record.actor],
              commands[index],
              itemRef,
              observed,
            );
          }
          assert.deepEqual(
            previous.operations,
            originals.map((record) => record.result.operation.operationId),
          );
          requireThat(
            previous.winner === actors[originalWinner].principalId,
            'RETAINED_BASELINE_REQUIRED',
          );
          const sealed = await assertEffects(4);
          assert.deepEqual(
            sealed.receipts.map((receipt) => receipt.operation_id),
            previous.operations,
          );
          requireThat(
            sealed.item[0].state === 'COMPLETED' &&
              sealed.item[0].claimant === previous.winner &&
              sealed.item[0].completer === previous.winner &&
              sealed.item[0].assignee === previous.winner,
            'COMPLETED_STATE',
          );
          await runKeyboardFollowup(itemRef, sealed);
          return;
        }

        let updated = await load('update');
        if (!updated) {
          await assertEffects(1);
          await refresh(checker);
          const stale = await inspect('checker', itemRef);
          const before = await snapshot();
          await inspect('maker', itemRef);
          assert.deepEqual(await snapshot(), before, 'Inspection has no effects');
          await maker
            .getByLabel('Transition reason', { exact: true })
            .fill('Replace retained diagnostic payload digest.');
          await maker
            .getByLabel('Replacement payload digest', { exact: true })
            .fill(`sha256:${'ab'.repeat(32)}`);
          updated = await capture('maker', 'update', 'UPDATE', () =>
            maker.getByRole('button', { name: 'Update work item', exact: true }).click(),
          );
          await checker
            .getByLabel('Transition reason', { exact: true })
            .fill('Reject this stale diagnostic update.');
          await checker
            .getByLabel('Replacement payload digest', { exact: true })
            .fill(`sha256:${'cd'.repeat(32)}`);
          const rejected = await capture('checker', 'stale-update', 'UPDATE', () =>
            checker.getByRole('button', { name: 'Update work item', exact: true }).click(),
          );
          requireThat(stale.workItem.revision === '1' && rejected.status === 412, 'STALE_UPDATE');
          await expect(
            checker.getByRole('region', { name: 'Work items', exact: true }).getByRole('alert'),
          ).toBeFocused();
          await checker
            .getByRole('button', { name: 'Dismiss rejected request and refresh', exact: true })
            .click();
        }
        updated = await recover('maker', 'update', 'UPDATE', itemRef);
        requireThat(updated.status === 202, 'UPDATE_REQUIRED');
        const staleUpdate = validateWorkItemRecord(
          await load('stale-update'),
          'checker',
          bindings.checker,
          'UPDATE',
          itemRef,
        );
        requireThat(staleUpdate.status === 412, 'STALE_UPDATE_REQUIRED');
        const beforeRace = await snapshot();
        const changedIntent = await browserPost(maker, {
          ...created.request,
          reason: 'Different intent under the consumed key.',
        });
        requireThat(changedIntent.status === 412, 'DIFFERENT_INTENT_DENIAL');
        assert.deepEqual(await snapshot(), beforeRace);

        let claims = await Promise.all(actorNames.map((name) => load(`claim-${name}`)));
        if (claims.every((record) => record === undefined)) {
          await assertEffects(2);
          for (const name of actorNames) {
            await refresh(pages[name]);
            requireThat((await inspect(name, itemRef)).workItem.revision === '2', 'CLAIM_REVISION');
            await pages[name]
              .getByLabel('Transition reason', { exact: true })
              .fill(`Claim this diagnostic case as ${name}.`);
          }
          let arrived = 0,
            release;
          const barrier = new Promise((done) => {
            release = done;
          });
          const gate = async () => {
            if (++arrived === 2) release();
            let timer;
            try {
              await Promise.race([
                barrier,
                new Promise((_, reject) => {
                  timer = setTimeout(
                    () => reject(new Error('WORK_ITEM_BROWSER_CLAIM_BARRIER')),
                    15000,
                  );
                }),
              ]);
            } finally {
              clearTimeout(timer);
            }
          };
          const outcomes = await Promise.allSettled(
            actorNames.map((name) =>
              capture(
                name,
                `claim-${name}`,
                'CLAIM',
                () =>
                  pages[name].getByRole('button', { name: 'Claim work item', exact: true }).click(),
                { gate },
              ),
            ),
          );
          const failed = outcomes.find((outcome) => outcome.status === 'rejected');
          if (failed) throw failed.reason;
          claims = outcomes.map((outcome) => outcome.value);
        } else {
          // Partial raced dispatch is retained as unresolved, never filled with a new intent.
          requireThat(claims.every(Boolean), 'PARTIAL_CLAIM_REQUIRES_ORIGINAL_REQUEST');
          for (const name of actorNames) await recover(name, `claim-${name}`, 'CLAIM', itemRef);
          claims = await Promise.all(actorNames.map((name) => load(`claim-${name}`)));
        }
        claims = claims.map((record) =>
          validateWorkItemRecord(record, record.actor, bindings[record.actor], 'CLAIM', itemRef),
        );
        const winner = workItemClaimWinner(claims),
          loser = actorNames.find((name) => name !== winner);
        await recover(winner, `claim-${winner}`, 'CLAIM', itemRef);
        const loserPage = pages[loser],
          winnerPage = pages[winner];
        const dismiss = loserPage.getByRole('button', {
          name: 'Dismiss rejected request and refresh',
          exact: true,
        });
        if (await dismiss.isVisible()) await dismiss.click();
        else await refresh(loserPage);

        let completed = await load('complete');
        if (!completed) {
          const effects = await assertEffects(3);
          requireThat(
            effects.item[0].assignee === actors[winner].principalId &&
              effects.item[0].claimant === actors[winner].principalId &&
              effects.item[0].completer === null,
            'CLAIMANT',
          );
          const wrongDetail = await inspect(loser, itemRef);
          await loserPage
            .getByLabel('Transition reason', { exact: true })
            .fill('A non-claimant cannot complete.');
          await expect(
            loserPage.getByRole('button', { name: 'Complete work item', exact: true }),
          ).toBeDisabled();
          const retainedWrong = await load('wrong-complete');
          const wrong = validateWorkItemRecord(
            retainedWrong ?? {
              actor: loser,
              request: {
                command: 'COMPLETE',
                actorKey: bindings[loser].actorKey,
                requestKey: randomUUID(),
                workItemRef: itemRef,
                expectedRevision: '3',
                etag: wrongDetail.etag,
                reason: 'Reject non-claimant completion.',
              },
            },
            loser,
            bindings[loser],
            'COMPLETE',
            itemRef,
          );
          if (retainedWrong) requireThat(wrong.status === 412, 'WRONG_CLAIMANT_UNRESOLVED');
          else {
            await save('wrong-complete', wrong);
            const wrongResult = await browserPost(loserPage, wrong.request);
            requireThat(
              wrongResult.status === 412 && wrongResult.body.code === 'PC-DATA-6007',
              'WRONG_CLAIMANT_DENIAL',
            );
            await save('wrong-complete', {
              ...wrong,
              status: 412,
              result: { code: wrongResult.body.code },
            });
          }
          assert.deepEqual(await snapshot(), effects);
          await winnerPage
            .getByLabel('Transition reason', { exact: true })
            .fill('Complete the claimed diagnostic work item.');
          completed = await capture(winner, 'complete', 'COMPLETE', () =>
            winnerPage.getByRole('button', { name: 'Complete work item', exact: true }).click(),
          );
        }
        completed = await recover(winner, 'complete', 'COMPLETE', itemRef);
        requireThat(completed.status === 202, 'COMPLETE_REQUIRED');
        requireThat(
          validateWorkItemRecord(
            await load('wrong-complete'),
            loser,
            bindings[loser],
            'COMPLETE',
            itemRef,
          ).status === 412,
          'WRONG_CLAIMANT_REQUIRED',
        );
        await expect(
          winnerPage.getByText('Current work-item state: COMPLETED.', { exact: true }),
        ).toBeVisible();
        const sealed = await assertEffects(4);
        const originalOperations = [
          created,
          updated,
          claims.find((record) => record.status === 202),
          completed,
        ].map((record) => record.result.operation.operationId);
        assert.deepEqual(
          sealed.receipts.map((receipt) => receipt.operation_id),
          originalOperations,
          'Each effect must belong to the original browser operation',
        );
        requireThat(
          sealed.item[0].state === 'COMPLETED' &&
            sealed.item[0].assignee === actors[winner].principalId &&
            sealed.item[0].completer === actors[winner].principalId,
          'COMPLETED_STATE',
        );

        const foreignBinding = await maker.request.get(
          `${origin}${endpoint}?${new URLSearchParams({ view: 'DETAIL', actorKey: bindings.checker.actorKey, workItemRef: itemRef })}`,
        );
        requireThat(
          foreignBinding.status() === 404 && (await foreignBinding.json()).code === 'PC-AUTH-0005',
          'FORGED_ACTOR_DENIAL',
        );
        const anonymous = await fetch(`${origin}${endpoint}?view=LIST`);
        requireThat(
          anonymous.status === 404 && (await anonymous.json()).code === 'PC-AUTH-0005',
          'ANONYMOUS_DENIAL',
        );
        const detailBefore = await read(winnerPage, {
          view: 'DETAIL',
          actorKey: bindings[winner].actorKey,
          workItemRef: itemRef,
        });
        const operationBefore = await read(winnerPage, {
          view: 'OPERATION',
          actorKey: bindings[winner].actorKey,
          operationId: completed.result.operation.operationId,
        });
        await exec(
          compose[0],
          [...compose.slice(1), 'restart', '--no-deps', 'control-api', 'admin-web'],
          { timeout: 90000, maxBuffer: 1024 * 1024 },
        );
        await expect
          .poll(
            async () => {
              try {
                return (await winnerPage.request.get(`${origin}${endpoint}?view=LIST`)).status();
              } catch {
                return 0;
              }
            },
            { timeout: 30000, intervals: [250, 500, 1000] },
          )
          .toBe(200);
        assert.deepEqual(
          await read(winnerPage, {
            view: 'DETAIL',
            actorKey: bindings[winner].actorKey,
            workItemRef: itemRef,
          }),
          detailBefore,
        );
        assert.deepEqual(
          await read(winnerPage, {
            view: 'OPERATION',
            actorKey: bindings[winner].actorKey,
            operationId: completed.result.operation.operationId,
          }),
          operationBefore,
        );
        assert.deepEqual(
          await assertEffects(4),
          sealed,
          'Restart must preserve original signed bytes and effects',
        );
        await winnerPage.reload();
        // Reload initially renders an unbound form. Wait for its real owner
        // read before filling, so hydration cannot replace the entered ID.
        await expect(
          winnerPage.getByRole('button', { name: 'Read operation', exact: true }),
        ).toBeEnabled();
        await winnerPage
          .getByLabel('Existing operation ID', { exact: true })
          .fill(completed.result.operation.operationId);
        await expect(winnerPage.getByLabel('Existing operation ID', { exact: true })).toHaveValue(
          completed.result.operation.operationId,
        );
        const readOperation = waitResponse(winnerPage, 'GET', 'OPERATION');
        await winnerPage.getByRole('button', { name: 'Read operation', exact: true }).click();
        requireThat((await readOperation).status() === 200, 'RESTART_UI_OPERATION');
        await winnerPage
          .getByRole('button', { name: 'Read operation work item', exact: true })
          .click();
        await expect(
          winnerPage.getByText('Current work-item state: COMPLETED.', { exact: true }),
        ).toBeVisible();

        // This fresh actor-scoped resource filter avoids assuming the whole shared store is empty.
        await winnerPage
          .getByRole('combobox', { name: /^Filter field/u })
          .selectOption('resourceRef');
        // The created item refers to maker; checker is the independent no-row reference.
        await winnerPage
          .getByLabel('Filter value', { exact: true })
          .fill(ref(actors.checker.principalId));
        await winnerPage.getByRole('combobox', { name: /^Sort/u }).selectOption('updatedAt');
        const emptyRead = waitResponse(winnerPage, 'GET', 'LIST');
        await winnerPage.getByRole('button', { name: 'Refresh work items', exact: true }).click();
        const empty = workItemView.parse(await (await emptyRead).json());
        requireThat(
          empty.kind === 'LIST' &&
            empty.page.authorizedEmpty &&
            empty.page.total === '0' &&
            empty.page.items.length === 0,
          'AUTHORIZED_EMPTY',
        );
        await expect(
          winnerPage.getByRole('button', { name: 'Next page', exact: true }),
        ).toBeDisabled();
        await winnerPage
          .getByLabel('Filter value', { exact: true })
          .fill(ref(actors.maker.principalId));
        await refresh(winnerPage);
        const listed = await read(winnerPage, {
          view: 'LIST',
          filter: `resourceRef:eq:${ref(actors.maker.principalId)}`,
          sort: 'updatedAt',
        });
        requireThat(
          listed.kind === 'LIST' &&
            listed.page.total === '1' &&
            listed.page.items.length === 1 &&
            listed.page.items[0].workItemId === itemRef,
          'LIST_COUNT',
        );
        await inspect(winner, itemRef);
        for (const width of [1440, 360]) {
          await winnerPage.setViewportSize({ width, height: 1000 });
          assert.deepEqual(
            (
              await new AxeBuilder({ page: winnerPage })
                .withTags(['wcag2a', 'wcag2aa', 'wcag21aa'])
                .analyze()
            ).violations,
            [],
          );
          requireThat(
            await winnerPage.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
            'REFLOW',
          );
          await winnerPage.screenshot({
            path: join(artifacts, `work-item-${width}.png`),
            fullPage: true,
          });
        }
        assert.deepEqual(await assertEffects(4), sealed);
        await save('result', {
          workItemRef: itemRef,
          winner: actors[winner].principalId,
          operations: originalOperations,
          state: 'COMPLETED',
          effects: 4,
          visualInspection: 'PENDING_INTEGRATOR',
        });
        process.stdout.write(
          'OPENPC_WORK_ITEM_BROWSER|PASS|real-authenticated-owners|create-update-claim-complete|original-recovery|one-claim-winner|denials|restart|signed-effects=4|completed-axe|completed-reflow|visual-inspection=PENDING\n',
        );
        await runKeyboardFollowup(itemRef, sealed);
      },
    );
  } finally {
    await pool.end();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch((error) => {
    // Playwright/SQL diagnostics may contain request or private fixture values.
    const boundary = /^WORK_ITEM_BROWSER_[A-Z_]+$/u.test(error?.message)
      ? error.message
      : 'WORK_ITEM_BROWSER_ASSERTION_OR_OWNER_FAILURE';
    const location = String(error?.stack ?? '').match(/work-item-browser\.mjs:(\d+):\d+/u)?.[1];
    process.stderr.write(
      `${boundary}|FAIL|${location ? `driver-line=${location}|` : ''}original-artifacts-retained\n`,
    );
    process.exitCode = 1;
  });
}
