import { afterEach, expect, it, vi } from 'vitest';

import {
  policySetDraftStorageKey,
  policyReleaseStorageKey,
  policyAuthorStorageKey,
  policyWorkflowPrivacyRevision,
  clearPolicyWorkflowStorage,
  clearTransactionWorkflowStorage,
  readBoundPolicyState,
  writeBoundPolicyState,
  type PolicyWorkflowActorBinding,
} from './policy-workflow-storage';

const actor: PolicyWorkflowActorBinding = {
  sessionId: '018f0000-0000-7000-8000-000000000117',
  principalId: '018f0000-0000-7000-8000-000000000111',
  participantId: '018f0000-0000-7000-8000-000000000101',
  privacyDomainId: '018f0000-0000-7000-8000-000000000201',
  contextEpoch: '2',
};
const valid = (value: unknown): value is { readonly resource: string } =>
  !!value &&
  typeof value === 'object' &&
  !Array.isArray(value) &&
  typeof (value as Record<string, unknown>).resource === 'string';

afterEach(() => {
  vi.restoreAllMocks();
  localStorage.clear();
});

it('restores only guarded state bound to the exact authoritative actor and context', () => {
  writeBoundPolicyState(policyReleaseStorageKey, actor, { resource: 'approved-release' });
  expect(readBoundPolicyState(policyReleaseStorageKey, actor, valid)).toEqual({
    resource: 'approved-release',
  });
  expect(
    readBoundPolicyState(
      policyReleaseStorageKey,
      { ...actor, principalId: '018f0000-0000-7000-8000-000000000112' },
      valid,
    ),
  ).toBeUndefined();
  expect(localStorage.getItem(policyReleaseStorageKey)).toBeNull();

  localStorage.setItem(policyReleaseStorageKey, '{not-json');
  expect(readBoundPolicyState(policyReleaseStorageKey, actor, valid)).toBeUndefined();
  expect(localStorage.getItem(policyReleaseStorageKey)).toBeNull();
});

it('keeps the authoritative workflow usable when browser storage is blocked', () => {
  vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
    throw new DOMException('blocked', 'SecurityError');
  });
  vi.spyOn(Storage.prototype, 'removeItem').mockImplementation(() => {
    throw new DOMException('blocked', 'SecurityError');
  });
  vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
    throw new DOMException('blocked', 'SecurityError');
  });
  expect(() => readBoundPolicyState(policyReleaseStorageKey, actor, valid)).not.toThrow();
  expect(() =>
    writeBoundPolicyState(policyReleaseStorageKey, actor, { resource: 'approved-release' }),
  ).not.toThrow();
});

it('fences late author persistence after explicit privacy cleanup or binding mismatch', () => {
  const initial = policyWorkflowPrivacyRevision();
  writeBoundPolicyState(policyAuthorStorageKey, actor, { resource: 'original' });
  clearPolicyWorkflowStorage();
  expect(policyWorkflowPrivacyRevision()).toBeGreaterThan(initial);
  expect(localStorage.getItem(policyAuthorStorageKey)).toBeNull();
  const cleared = policyWorkflowPrivacyRevision();
  writeBoundPolicyState(policyAuthorStorageKey, actor, { resource: 'original' });
  readBoundPolicyState(policyAuthorStorageKey, { ...actor, contextEpoch: '3' }, valid);
  expect(policyWorkflowPrivacyRevision()).toBeGreaterThan(cleared);
  expect(localStorage.getItem(policyAuthorStorageKey)).toBeNull();
});

it('clears policy-set draft text and actor binding at a privacy transition', () => {
  writeBoundPolicyState(policySetDraftStorageKey, actor, {
    name: 'Private draft',
    reason: 'Private reason',
    requestKey: 'original',
    selected: '',
  });
  clearPolicyWorkflowStorage();
  expect(localStorage.getItem(policySetDraftStorageKey)).toBeNull();
});

it('clears every scoped transaction request without removing unrelated custody', () => {
  const requests = [
    'openpc:transaction-workbench:v1:modules',
    'openpc:transaction-workbench:v1:evidence:evidence-deletion:original-object',
    'openpc:transaction-workbench:v1:runtime:original-target',
  ];
  for (const key of requests) localStorage.setItem(key, 'retained request');
  localStorage.setItem('openpc:rpc-platform-envelope:v1', 'original envelope');
  localStorage.setItem('openpc:transaction-workbench:v2:modules', 'another owner');
  clearTransactionWorkflowStorage();
  for (const key of requests) expect(localStorage.getItem(key)).toBeNull();
  expect(localStorage.getItem('openpc:rpc-platform-envelope:v1')).toBe('original envelope');
  expect(localStorage.getItem('openpc:transaction-workbench:v2:modules')).toBe('another owner');
});

it('allows authoritative sign-out readback when cache enumeration is blocked', () => {
  vi.spyOn(Storage.prototype, 'key').mockImplementation(() => {
    throw new DOMException('blocked', 'SecurityError');
  });
  localStorage.setItem('openpc:transaction-workbench:v1:modules', 'retained request');
  expect(() => clearTransactionWorkflowStorage()).not.toThrow();
});
