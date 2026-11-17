import { expect, it } from 'vitest';
import {
  notificationProviderFrame,
  notificationProviderProtocol,
  notificationProviderRequest,
  notificationProviderFrameLimit,
  notificationProviderChunkBytes,
} from './credential-provider-client.js';
const id = '018f0000-0000-7000-8000-000000000101';
const request = {
  participantId: id,
  privacyDomainId: id,
  credentialRef: `urn:openpc:resource:${id}`,
  reference: 'secret://local/notification#1',
  version: '1',
  epoch: '1',
  purpose: 'NOTIFICATION_GATEWAY_CREDENTIAL',
  consumer: 'LS-NOTIFICATION',
};
const bound = {
  protocol: notificationProviderProtocol,
  nonce: 'a'.repeat(64),
  requestDigest: `sha256:${'b'.repeat(64)}`,
  leaseId: 'c'.repeat(64),
};
it('closes the provider request to the exact existing export purpose, version and scope', () => {
  expect(notificationProviderRequest.parse(request)).toEqual(request);
  for (const change of [
    { ready: true },
    { purpose: 'EVIDENCE_KEY' },
    { consumer: 'LS-FACT-BRIDGE' },
    { reference: 'secret://local/notification#latest' },
    { epoch: '0' },
    { participantId: 'foreign' },
    { version: '' },
  ])
    expect(notificationProviderRequest.safeParse({ ...request, ...change }).success).toBe(false);
});
it('bounds frames and forbids protocol substitution, extra material and unknown phases', () => {
  expect(notificationProviderFrameLimit).toBe(65536);
  expect(notificationProviderChunkBytes).toBe(32768);
  for (const type of ['USE', 'USING', 'FINALIZE', 'FINALIZED', 'CANCEL'])
    expect(notificationProviderFrame.parse({ ...bound, type })).toEqual({ ...bound, type });
  for (const frame of [
    { ...bound, type: 'FINALIZE', material: 'secret' },
    { ...bound, type: 'RETRY' },
    { ...bound, type: 'USE', protocol: 'OTHER' },
    { ...bound, type: 'USE', nonce: 'a' },
    { ...bound, type: 'RELEASE', outcome: 'UNKNOWN' },
    { ...bound, type: 'OPENED', deadline: 1, encoding: 'RAW', materialLength: 1 },
    {
      ...bound,
      type: 'OPENED',
      deadline: 1,
      encoding: 'OPENPC_NOTIFICATION_MTLS_1',
      materialLength: 65537,
    },
    {
      ...bound,
      type: 'OPENED',
      deadline: Infinity,
      encoding: 'OPENPC_NOTIFICATION_MTLS_1',
      materialLength: 1,
    },
    { ...bound, type: 'CHUNK', offset: 0, material: 'A'.repeat(43693) },
    { ...bound, type: 'FETCH', offset: 32769 },
  ])
    expect(notificationProviderFrame.safeParse(frame).success).toBe(false);
});
