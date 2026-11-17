import { expect, it } from 'vitest';
import {
  endpointCommand,
  endpointCreateAction,
  endpointUpdateAction,
  endpointReplacements,
  endpointDefiniteRejection,
  endpointOperationMatches,
  endpointPending,
  endpointQuery,
  endpointRecord,
  endpointRequestKey,
  endpointVerifyActionId,
} from './notification-endpoint-workflow';
const id = (n: number) => `01900000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const hash = `sha256:${'a'.repeat(64)}`;
const request = {
  command: 'VERIFY' as const,
  actorKey: hash,
  requestKey: id(1),
  endpointRef: `urn:openpc:resource:${id(2)}`,
  expectedRevision: '1',
  etag: `"${hash}"`,
  reason: 'Verify the admitted endpoint.',
};
const item = {
  notificationEndpointId: request.endpointRef,
  participantId: `urn:openpc:participant:${id(3)}`,
  channel: 'WEBHOOK',
  destinationRef: `urn:openpc:resource:${id(4)}`,
  arbitraryEgress: false,
  state: 'DISABLED',
  revision: '1',
  createdAt: '2026-09-25T00:00:00.000000Z',
  updatedAt: '2026-09-25T00:00:00.000000Z',
};
it('accepts only canonical revisions, exact resource identities and bounded public inputs', () => {
  expect(endpointCommand.parse(request)).toEqual(request);
  for (const expectedRevision of ['0', '01', '-1', ' 1', '18446744073709551616'])
    expect(endpointCommand.safeParse({ ...request, expectedRevision }).success).toBe(false);
  for (const endpointRef of [
    'https://unapproved.invalid',
    `urn:openpc:participant:${id(2)}`,
    `${request.endpointRef}\n`,
  ])
    expect(endpointCommand.safeParse({ ...request, endpointRef }).success).toBe(false);
  expect(
    endpointCommand.safeParse({ ...request, credentialRef: item.destinationRef }).success,
  ).toBe(false);
  expect(endpointCommand.safeParse({ ...request, reason: 'x'.repeat(8192) }).success).toBe(false);
  expect(endpointCommand.safeParse({ ...request, command: 'DISABLE' }).success).toBe(false);
});
it('projects all four endpoint states without claiming private credential or proof information', () => {
  for (const state of ['DISABLED', 'ACTIVE', 'QUARANTINED', 'RETIRED'])
    expect(endpointRecord.parse({ ...item, state }).state).toBe(state);
  for (const extra of [
    { credentialRef: item.destinationRef },
    { challengeBytes: 'private' },
    { signedReceipt: 'private' },
    { arbitraryEgress: true },
  ])
    expect(endpointRecord.safeParse({ ...item, ...extra }).success).toBe(false);
  expect(endpointQuery.safeParse({ view: 'LIST', filter: 'credentialRef:eq:hidden' }).success).toBe(
    false,
  );
  expect(endpointQuery.parse({ view: 'LIST', filter: 'state:eq:DISABLED' })).toMatchObject({
    limit: '25',
    sort: '-updatedAt',
  });
});
it('retains UNKNOWN and malformed/transport failures instead of treating every 409 as rejection', () => {
  const problem = {
    type: 'https://errors.openpc.local/conflict',
    title: 'Unknown',
    status: 409,
    code: 'PC-FACT-4001',
    truthState: 'UNKNOWN',
    retryable: false,
    traceId: id(9),
  };
  expect(endpointDefiniteRejection(problem, 409)).toBe(false);
  expect(endpointDefiniteRejection({ ...problem, truthState: 'FAILED' }, 409)).toBe(false);
  expect(endpointDefiniteRejection(undefined, 503)).toBe(false);
  const stale = {
    ...problem,
    type: 'https://errors.openpc.local/stale',
    status: 412,
    code: 'PC-DATA-6007',
    truthState: 'STALE',
  };
  expect(endpointDefiniteRejection(stale, 412)).toBe(true);
  expect(endpointDefiniteRejection(stale, 409)).toBe(false);
});
it('recovery hints bind the original endpoint and request, never a substitute operation', () => {
  const saved = { request, uncertain: true };
  expect(endpointPending.parse(saved)).toEqual(saved);
  expect(endpointPending.safeParse({ ...saved, lease: 'fabricated' }).success).toBe(false);
  const operation = {
    operationId: id(5),
    resourceRef: request.endpointRef,
    actionIntentId: endpointVerifyActionId,
    intentDigest: hash,
    idempotencyKey: endpointRequestKey(request.requestKey),
    state: 'SUCCEEDED' as const,
    truthState: 'SUCCESS' as const,
    revision: '2',
    createdAt: item.createdAt,
    updatedAt: item.updatedAt,
  };
  expect(endpointOperationMatches(operation, request)).toBe(true);
  for (const changed of [
    { resourceRef: item.destinationRef },
    { idempotencyKey: 'different-original-key' },
    { actionIntentId: 'ACT-NOTIFICATION_UPDATE_ACKNOWLEDGE-V1' },
  ])
    expect(endpointOperationMatches({ ...operation, ...changed }, request)).toBe(false);
});

it('retains only a reviewed CREATE request and correlates its owner-allocated resource operation', () => {
  const review = {
    command: 'REVIEW_CREATE',
    actorKey: hash,
    requestKey: id(6),
    channel: 'WEBHOOK',
    destinationRef: item.destinationRef,
    arbitraryEgress: false,
    reason: 'Create admitted metadata.',
  };
  expect(endpointCommand.safeParse(review).success).toBe(true);
  expect(endpointPending.safeParse({ request: review, uncertain: true }).success).toBe(false);
  const create = endpointCommand.options[1].parse({
    ...review,
    command: 'CREATE',
    candidateDigest: hash,
  });
  expect(endpointPending.parse({ request: create, uncertain: true }).request).toEqual(create);
  for (const changed of [
    { ...create, candidateDigest: undefined },
    { ...create, participantId: item.participantId },
    { ...create, credentialRef: item.destinationRef },
    { ...create, stepUpVerified: true },
  ])
    expect(endpointCommand.safeParse(changed).success).toBe(false);
  const operation = {
    operationId: id(8),
    resourceRef: request.endpointRef,
    actionIntentId: endpointCreateAction.id,
    intentDigest: endpointCreateAction.digest,
    idempotencyKey: endpointRequestKey(create.requestKey),
    state: 'SUCCEEDED' as const,
    truthState: 'SUCCESS' as const,
    revision: '1',
    createdAt: item.createdAt,
    updatedAt: item.updatedAt,
  };
  expect(endpointOperationMatches(operation, create)).toBe(true);
  expect(
    endpointOperationMatches({ ...operation, idempotencyKey: endpointRequestKey(id(7)) }, create),
  ).toBe(false);
  expect(endpointOperationMatches({ ...operation, resourceRef: item.participantId }, create)).toBe(
    false,
  );
});

it('binds UPDATE recovery to its original selected digest, endpoint, revision and request key', () => {
  const input = endpointCommand.options[2].parse({
    ...request,
    command: 'UPDATE',
    replacementDigest: hash,
    candidateDigest: hash,
  });
  expect(endpointPending.parse({ request: input, uncertain: true }).request).toEqual(input);
  const operation = {
    operationId: id(8),
    resourceRef: input.endpointRef,
    actionIntentId: endpointUpdateAction.id,
    intentDigest: endpointUpdateAction.digest,
    idempotencyKey: endpointRequestKey(input.requestKey),
    state: 'SUCCEEDED' as const,
    truthState: 'SUCCESS' as const,
    revision: '2',
    createdAt: item.createdAt,
    updatedAt: item.updatedAt,
  };
  expect(endpointOperationMatches(operation, input)).toBe(true);
  for (const changed of [
    { resourceRef: item.destinationRef },
    { actionIntentId: endpointVerifyActionId },
    { idempotencyKey: endpointRequestKey(id(9)) },
  ])
    expect(endpointOperationMatches({ ...operation, ...changed }, input)).toBe(false);
  const choice = {
    channel: item.channel,
    destinationRef: item.destinationRef,
    replacementDigest: hash,
  };
  const choices = {
    notificationEndpointId: input.endpointRef,
    revision: input.expectedRevision,
    authority: 'NONE',
    items: [choice],
  };
  expect(endpointReplacements.parse(choices)).toEqual(choices);
  for (const changed of [
    { ...choices, authority: 'AUTHORIZED' },
    { ...choices, items: [{ ...choice, credentialRef: item.destinationRef }] },
    { ...choices, items: Array.from({ length: 65 }, () => choice) },
  ])
    expect(endpointReplacements.safeParse(changed).success).toBe(false);
});
