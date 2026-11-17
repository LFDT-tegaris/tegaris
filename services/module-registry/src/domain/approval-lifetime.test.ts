import { describe, expect, it } from 'vitest';
import { policyApprovalTtlMs } from './approval-lifetime.js';

describe('new policy approval lifetime configuration', () => {
  const qa = {
    OPENPC_LOCAL_RUNTIME: '1',
    OPENPC_LOCAL_RUNTIME_QA_FIXTURE: '1',
    OPENPC_LOCAL_QA_DURATION_PROFILE: 'LOCAL_QA_10X',
  };
  it('scales only new approvals under the exact local QA profile within the original ceiling', () => {
    expect(policyApprovalTtlMs(qa)).toBe(18_000_000);
    expect(policyApprovalTtlMs({ ...qa, POLICY_APPROVAL_TTL_MS: '300000' })).toBe(3_000_000);
    expect(() => policyApprovalTtlMs({ ...qa, POLICY_APPROVAL_TTL_MS: '2592000000' })).toThrow(
      'Invalid POLICY_APPROVAL_TTL_MS',
    );
    expect(() => policyApprovalTtlMs({ ...qa, OPENPC_LOCAL_RUNTIME_QA_FIXTURE: '0' })).toThrow(
      'explicit local QA',
    );
    expect(policyApprovalTtlMs({})).toBe(1_800_000);
  });
  it.each([
    ['300000', 300_000, 3_000_000],
    ['1800000', 1_800_000, 18_000_000],
    ['259200000', 259_200_000, 2_592_000_000],
  ] as const)(
    'treats explicit %s as the normal baseline in both profiles',
    (raw, normal, extended) => {
      expect(policyApprovalTtlMs({ POLICY_APPROVAL_TTL_MS: raw })).toBe(normal);
      expect(policyApprovalTtlMs({ ...qa, POLICY_APPROVAL_TTL_MS: raw })).toBe(extended);
    },
  );
  it.each(['259200001', '2592000000'])(
    'rejects a normal-valid value %s when its QA duration exceeds the finite ceiling',
    (raw) => {
      expect(policyApprovalTtlMs({ POLICY_APPROVAL_TTL_MS: raw })).toBe(Number(raw));
      expect(() => policyApprovalTtlMs({ ...qa, POLICY_APPROVAL_TTL_MS: raw })).toThrow(
        'Invalid POLICY_APPROVAL_TTL_MS',
      );
    },
  );
  it('preserves the default and permits longer explicit QA configuration', () => {
    expect(policyApprovalTtlMs({})).toBe(1_800_000);
    expect(policyApprovalTtlMs({ POLICY_APPROVAL_TTL_MS: '28800000' })).toBe(28_800_000);
    expect(policyApprovalTtlMs({ POLICY_APPROVAL_TTL_MS: '300000' })).toBe(300_000);
    expect(policyApprovalTtlMs({ POLICY_APPROVAL_TTL_MS: '2592000000' })).toBe(2_592_000_000);
  });
  it.each([
    '',
    '0',
    '-1',
    '299999',
    '2592000001',
    '9007199254740992',
    'Infinity',
    '3e5',
    '300000.5',
  ])('rejects invalid bound %s', (value) => {
    expect(() => policyApprovalTtlMs({ POLICY_APPROVAL_TTL_MS: value })).toThrow(
      'Invalid POLICY_APPROVAL_TTL_MS',
    );
    expect(() => policyApprovalTtlMs({ ...qa, POLICY_APPROVAL_TTL_MS: value })).toThrow(
      'Invalid POLICY_APPROVAL_TTL_MS',
    );
  });
});

it('keeps approval expiry unchanged under an execution-only profile', () => {
  expect(
    policyApprovalTtlMs({
      OPENPC_LOCAL_RUNTIME: '1',
      OPENPC_LOCAL_RUNTIME_QA_FIXTURE: '1',
      OPENPC_LOCAL_QA_EXECUTION_PROFILE: 'LOCAL_QA_10X',
      POLICY_APPROVAL_TTL_MS: '1800000',
    }),
  ).toBe(1_800_000);
});
