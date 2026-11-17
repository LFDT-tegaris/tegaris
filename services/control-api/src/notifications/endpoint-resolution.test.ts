import { afterEach, expect, it, vi } from 'vitest';
import type { PoolClient } from 'pg';
import type { MutationContext } from '../configuration/persistence/types.js';
import {
  NotificationEndpointResolution,
  endpointRequest,
  type EndpointCommand,
} from './endpoint-resolution.js';
import {
  endpointBinding,
  type NotificationEndpointBusinessState,
} from './endpoint-business-state.js';
import {
  notificationEndpointReplacementDigest,
  type NotificationEndpointConstruction,
  type NotificationEndpointOwners,
  type NotificationEndpointVerificationObservation,
} from './endpoint-owner-contract.js';

// Isolated consumer/correlation tests. Owner doubles below supply untrusted test
// values; they do NOT establish authentication, installation, SQL or API acceptance.
const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const ref = (n: number) => `urn:openpc:resource:${id(n)}`;
const digest = (n: string) => `sha256:${n.repeat(64)}`;
const client = Object.freeze({}) as PoolClient;
const before: NotificationEndpointBusinessState = {
  participantId: id(1),
  privacyDomainId: id(2),
  endpointId: id(3),
  revision: '7',
  channel: 'WEBHOOK',
  destinationRef: ref(4),
  channelProfileDigest: digest('a'),
  credentialRef: ref(5),
  state: 'DISABLED',
  arbitraryEgress: false,
  candidateDigest: digest('b'),
  verificationId: null,
};
const construction: NotificationEndpointConstruction = {
  binding: { ...endpointBinding(before), revision: '8' },
  credential: {
    participantId: id(1),
    privacyDomainId: id(2),
    channel: 'WEBHOOK',
    destinationRef: ref(4),
    credentialRef: ref(5),
    secretClass: 'SECRET-NOTIFICATION-CREDENTIAL',
    owner: 'LS-NOTIFICATION',
    reference: 'secret://fixture/channel#v7',
    version: 'v7',
    fingerprint: digest('c'),
    epoch: '7',
    validFromMs: 1000,
    validUntilMs: 3000,
    state: 'ACTIVE',
  },
};
const envelope = { actionIntentDigest: digest('d'), reason: 'Inspect the exact retained binding.' };
const create = {
  ...envelope,
  actionIntentId: 'ACT-NOTIFICATION_ENDPOINTS_CREATE_RESOURCE-V1',
  participantId: `urn:openpc:participant:${id(1)}`,
  channel: 'WEBHOOK' as const,
  destinationRef: ref(4),
  arbitraryEgress: false as const,
};
const update = {
  ...envelope,
  actionIntentId: 'ACT-NOTIFICATION_ENDPOINTS_UPDATE_RESOURCE-V1',
  expectedRevision: '7',
  replacementDigest: notificationEndpointReplacementDigest(endpointBinding(before), construction),
};
const verify = {
  ...envelope,
  actionIntentId: 'ACT-NOTIFICATION_UPDATE_VERIFY-V1',
  expectedRevision: '7',
  targetRef: ref(3),
  inputDigest: digest('e'),
};
function context(
  command: EndpointCommand,
  candidate: typeof create | typeof update | typeof verify,
): MutationContext {
  return {
    authorization: { participantId: id(1), privacyDomainId: id(2) },
    resourceId: id(3),
    expectedRevision: command === 'CREATE' ? '0' : '7',
    candidate,
    aggregateType: 'notification-endpoint',
    catalogOperationId: `CFG-OP-${command}-NOTIFICATION-ENDPOINT`,
    actionIntentId: candidate.actionIntentId,
    actionIntentDigest: candidate.actionIntentDigest,
    resourceType: command === 'VERIFY' ? 'notification-endpoint' : 'notification-endpoints',
    operationClass: command === 'CREATE' ? 'CREATE' : 'UPDATE',
  } as MutationContext;
}
function owners(value: NotificationEndpointConstruction = construction) {
  const observation: NotificationEndpointVerificationObservation = {
    verificationId: id(8),
    operationId: id(9),
    inputDigest: verify.inputDigest,
    predecessor: endpointBinding(before),
    result: value,
    observationDigest: digest('f'),
    observedAtMs: 1200,
    validUntilMs: 2500,
  };
  return {
    resolveCreate: vi.fn(async () => value),
    resolveReplacement: vi.fn(async () => value),
    verify: vi.fn(async () => observation),
  } satisfies NotificationEndpointOwners;
}
afterEach(() => vi.restoreAllMocks());

it('keeps owners constructor-only and rejects missing construction without touching SQL', async () => {
  const resolution = new NotificationEndpointResolution();
  await expect(resolution.create(client, context('CREATE', create), create)).rejects.toThrow(
    'PC-INTEGRATION-5001',
  );
  await expect(
    resolution.replacement(client, context('UPDATE', update), before, update),
  ).rejects.toThrow('PC-INTEGRATION-5001');
  await expect(
    resolution.verify(client, context('VERIFY', verify), id(9), before, verify),
  ).rejects.toThrow('PC-INTEGRATION-5001');
  expect(() =>
    endpointRequest(context('CREATE', create), 'CREATE', { ...create, owners: owners() }),
  ).toThrow('PC-DATA-6007');
});

it('passes the same transaction and checks creation scope and exact original public input', async () => {
  vi.spyOn(Date, 'now').mockReturnValue(1500);
  const selected = { ...construction, binding: { ...construction.binding, revision: '1' } };
  const implementation = owners(selected),
    request = context('CREATE', create);
  const resolution = new NotificationEndpointResolution(implementation);
  expect(await resolution.create(client, request, create)).toEqual(selected);
  expect(implementation.resolveCreate).toHaveBeenCalledWith(client, request, create);
  const foreign = { ...selected, binding: { ...selected.binding, endpointId: id(10) } };
  await expect(
    new NotificationEndpointResolution(owners(foreign)).create(client, request, create),
  ).rejects.toThrow('PC-DATA-6007');
  for (const patch of [
    { reason: 'Changed original' },
    { participantId: `urn:openpc:participant:${id(10)}` },
    { arbitraryEgress: true },
    { destinationRef: ref(10) },
  ])
    await expect(
      resolution.create(client, request, { ...create, ...patch } as typeof create),
    ).rejects.toThrow('PC-DATA-6007');
  expect(implementation.resolveCreate).toHaveBeenCalledTimes(1);
});

it('never turns an arbitrary replacement digest into a candidate or reuses a stale predecessor', async () => {
  vi.spyOn(Date, 'now').mockReturnValue(1500);
  const implementation = owners(),
    resolution = new NotificationEndpointResolution(implementation);
  expect(await resolution.replacement(client, context('UPDATE', update), before, update)).toEqual(
    construction,
  );
  expect(implementation.resolveReplacement).toHaveBeenCalledWith(
    client,
    context('UPDATE', update),
    before,
    update,
  );
  for (const patch of [
    { revision: '6' },
    { privacyDomainId: id(10) },
    { state: 'RETIRED' as const },
  ])
    await expect(
      resolution.replacement(client, context('UPDATE', update), { ...before, ...patch }, update),
    ).rejects.toThrow('PC-DATA-6007');
  expect(implementation.resolveReplacement).toHaveBeenCalledTimes(1);
  const altered = { ...update, replacementDigest: digest('0') };
  await expect(
    resolution.replacement(client, context('UPDATE', altered), before, altered),
  ).rejects.toThrow('PC-DATA-6007');
  for (const credential of [
    { ...construction.credential, state: 'REVOKED' as const },
    { ...construction.credential, validUntilMs: 1500 },
    { ...construction.credential, epoch: '8' },
  ])
    await expect(
      new NotificationEndpointResolution(owners({ ...construction, credential })).replacement(
        client,
        context('UPDATE', update),
        before,
        update,
      ),
    ).rejects.toThrow('PC-DATA-6007');
});

it('binds verification to the original operation and both revisions without changing routing', async () => {
  vi.spyOn(Date, 'now').mockReturnValue(1500);
  const implementation = owners(),
    resolution = new NotificationEndpointResolution(implementation);
  const request = context('VERIFY', verify);
  const observed = await resolution.verify(client, request, id(9), before, verify);
  expect(observed.result.binding.revision).toBe('8');
  expect(implementation.verify).toHaveBeenCalledWith(client, request, id(9), before, verify);
  await expect(resolution.verify(client, request, id(10), before, verify)).rejects.toThrow(
    'PC-DATA-6007',
  );
  for (const state of ['QUARANTINED', 'RETIRED'] as const)
    await expect(
      resolution.verify(client, request, id(9), { ...before, state }, verify),
    ).rejects.toThrow('PC-DATA-6007');
  const changed = {
    ...construction,
    binding: { ...construction.binding, channelProfileDigest: digest('0') },
  };
  await expect(
    new NotificationEndpointResolution(owners(changed)).verify(
      client,
      request,
      id(9),
      before,
      verify,
    ),
  ).rejects.toThrow('PC-DATA-6007');
  vi.spyOn(Date, 'now').mockReturnValue(2500);
  await expect(resolution.verify(client, request, id(9), before, verify)).rejects.toThrow(
    'PC-DATA-6007',
  );
});
