import { expect, it } from 'vitest';
import {
  assertNotificationEndpointConstruction,
  assertNotificationEndpointVerificationObservation,
  notificationChannelCredential,
  notificationEndpointReplacementDigest,
  requireNotificationEndpointOwners,
  type NotificationEndpointOwners,
  type NotificationEndpointConstruction,
  type NotificationEndpointVerificationObservation,
} from './endpoint-owner-contract.js';
import type { NotificationEndpointBusinessState } from './endpoint-business-state.js';

// Shape/correlation corpus only. No installed provider, admitted candidate,
// authenticated verification, signed business transition or runtime is mocked.
const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const ref = (n: number) => `urn:openpc:resource:${id(n)}`;
const hash = (n: string) => `sha256:${n.repeat(64)}`;
const before: NotificationEndpointBusinessState = {
  participantId: id(1),
  privacyDomainId: id(2),
  endpointId: id(3),
  revision: '7',
  channel: 'WEBHOOK',
  destinationRef: ref(4),
  channelProfileDigest: hash('a'),
  credentialRef: ref(5),
  state: 'DISABLED',
  arbitraryEgress: false,
  candidateDigest: hash('b'),
  verificationId: null,
};
const binding = {
  participantId: before.participantId,
  privacyDomainId: before.privacyDomainId,
  endpointId: before.endpointId,
  revision: '8',
  channel: before.channel,
  destinationRef: before.destinationRef,
  channelProfileDigest: before.channelProfileDigest,
  credentialRef: before.credentialRef,
};
const construction: NotificationEndpointConstruction = {
  binding,
  credential: {
    participantId: id(1),
    privacyDomainId: id(2),
    credentialRef: ref(5),
    channel: 'WEBHOOK',
    destinationRef: ref(4),
    secretClass: 'SECRET-NOTIFICATION-CREDENTIAL',
    owner: 'LS-NOTIFICATION',
    reference: 'secret://fixture/notification-channel#v7',
    version: 'v7',
    fingerprint: hash('c'),
    epoch: '7',
    validFromMs: 1000,
    validUntilMs: 3000,
    state: 'ACTIVE',
  },
};
const command = { operationId: id(6), inputDigest: hash('d') };
const observation: NotificationEndpointVerificationObservation = {
  ...command,
  verificationId: id(7),
  predecessor: { ...binding, revision: '7' },
  result: construction,
  observationDigest: hash('e'),
  observedAtMs: 1400,
  validUntilMs: 2000,
};

it('has no permissive construction fallback while an authoritative owner is missing', () => {
  for (const value of [undefined, null, {}, { current: true }, { resolveCreate: 'ready' }])
    expect(() =>
      requireNotificationEndpointOwners(value as NotificationEndpointOwners | undefined),
    ).toThrow('PC-INTEGRATION-5001');
});

it('requires an exact versioned provider credential, separate from workload identity and bytes', () => {
  expect(notificationChannelCredential.parse(construction.credential)).toEqual(
    construction.credential,
  );
  for (const patch of [
    { reference: 'secret://fixture/channel#latest', version: 'latest' },
    { reference: 'secret://fixture/channel#current', version: 'current' },
    { version: 'different' },
    { reference: 'inline-private-key' },
    { credentialRef: `urn:openpc:credential:${id(5)}` },
    { secretClass: 'SECRET-WORKLOAD-CERTIFICATE' },
    { owner: 'LS-CONTROL-API' },
    { current: true },
    { bytes: 'secret' },
    { workloadCredentialEpoch: '7' },
    { epoch: '0' },
    { epoch: '7\n' },
    { credentialRef: `${ref(5)}\n` },
    { fingerprint: `${hash('c')}\n` },
  ])
    expect(
      notificationChannelCredential.safeParse({ ...construction.credential, ...patch }).success,
    ).toBe(false);
});

it('rejects cross-scope, destination, revision, expired and revoked construction metadata', () => {
  expect(assertNotificationEndpointConstruction(binding, construction, 1500)).toEqual(construction);
  for (const patch of [
    { participantId: id(9) },
    { privacyDomainId: id(9) },
    { destinationRef: ref(9) },
    { credentialRef: ref(9) },
    { channel: 'EMAIL' },
    { validFromMs: 1600 },
    { validUntilMs: 1500 },
    { state: 'REVOKED' },
    { state: 'RETIRED' },
  ])
    expect(() =>
      assertNotificationEndpointConstruction(
        binding,
        {
          ...construction,
          credential: { ...construction.credential, ...patch },
        },
        1500,
      ),
    ).toThrow('PC-DATA-6007');
  for (const patch of [
    { revision: '7' },
    { endpointId: id(9) },
    { channelProfileDigest: hash('f') },
  ])
    expect(() =>
      assertNotificationEndpointConstruction({ ...binding, ...patch }, construction, 1500),
    ).toThrow('PC-DATA-6007');
});

it('binds replacement digests to original revision, selected profile and immutable credential epoch', () => {
  const prior = observation.predecessor;
  const digest = notificationEndpointReplacementDigest(prior, construction);
  expect(notificationEndpointReplacementDigest(prior, structuredClone(construction))).toBe(digest);
  for (const patch of [
    { epoch: '8' },
    { fingerprint: hash('f') },
    {
      reference: 'secret://fixture/notification-channel#v8',
      version: 'v8',
    },
  ])
    expect(
      notificationEndpointReplacementDigest(prior, {
        ...construction,
        credential: { ...construction.credential, ...patch },
      }),
    ).not.toBe(digest);
  expect(
    notificationEndpointReplacementDigest(prior, {
      ...construction,
      binding: { ...binding, channelProfileDigest: hash('f') },
    }),
  ).not.toBe(digest);
  for (const patch of [{ revision: '7' }, { revision: '9' }, { privacyDomainId: id(9) }])
    expect(() =>
      notificationEndpointReplacementDigest(prior, {
        ...construction,
        binding: { ...binding, ...patch },
      }),
    ).toThrow();
});

it('verification correlates exact predecessor, next revision and operation without lifting quarantine', () => {
  expect(
    assertNotificationEndpointVerificationObservation(before, command, observation, 1500),
  ).toEqual(observation);
  for (const patch of [
    { operationId: id(9) },
    { inputDigest: hash('f') },
    { observedAtMs: 1600 },
    { validUntilMs: 1500 },
    { validUntilMs: 3001 },
    { authenticated: true },
    { predecessor: { ...observation.predecessor, revision: '6' } },
    { result: { ...construction, binding: { ...binding, revision: '9' } } },
    { result: { ...construction, binding: { ...binding, channelProfileDigest: hash('f') } } },
  ])
    expect(() =>
      assertNotificationEndpointVerificationObservation(
        before,
        command,
        {
          ...observation,
          ...patch,
        },
        1500,
      ),
    ).toThrow('PC-DATA-6007');
  for (const state of ['QUARANTINED', 'RETIRED'] as const)
    expect(() =>
      assertNotificationEndpointVerificationObservation(
        { ...before, state },
        command,
        observation,
        1500,
      ),
    ).toThrow('PC-DATA-6007');
  expect(() =>
    assertNotificationEndpointVerificationObservation(
      { ...before, arbitraryEgress: true } as unknown as NotificationEndpointBusinessState,
      command,
      observation,
      1500,
    ),
  ).toThrow();
});
