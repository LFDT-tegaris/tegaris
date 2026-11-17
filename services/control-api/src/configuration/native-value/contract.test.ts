import { describe, expect, it } from 'vitest';
import { createNativeValueAuthorizationSchema } from './contract.js';

const input = {
  actionIntentId: 'ACT-NATIVE_VALUE_AUTHORIZATIONS_CREATE_RESOURCE-V1',
  actionIntentDigest: `sha256:${'11'.repeat(32)}`,
  reason: 'Authorize a bounded test contract endowment.',
  walletBindingId: 'urn:openpc:resource:018f0000-0000-7000-8000-000000000001',
  chainId: '92870',
  networkId: 'devnet',
  genesisDigest: `sha256:${'22'.repeat(32)}`,
  amountMode: 'EXACT',
  maxAmountWei: '10',
  validUntil: '2030-01-01T00:00:00.000Z',
};

describe('Native Value authorization command input', () => {
  it('accepts exact reviewed limits and an optional real workload reference', () => {
    expect(createNativeValueAuthorizationSchema.parse(input)).toEqual(input);
    expect(
      createNativeValueAuthorizationSchema.safeParse({
        ...input,
        amountMode: 'MAXIMUM',
        executionWorkloadId: 'urn:openpc:workload:018f0000-0000-7000-8000-000000000002',
      }).success,
    ).toBe(true);
  });
  it('rejects caller-supplied authority, owner identity and consumption state', () => {
    for (const [field, value] of Object.entries({
      participantEpoch: '1',
      actorSubjectId: 'actor:forged',
      purpose: 'NATIVE_TRANSFER',
      oneUse: true,
      used: false,
      policyDecisionDigest: '33'.repeat(32),
      semanticDigest: '44'.repeat(32),
      ready: true,
    }))
      expect(
        createNativeValueAuthorizationSchema.safeParse({ ...input, [field]: value }).success,
        field,
      ).toBe(false);
  });
  it('rejects ambiguous amounts, unbounded chains and malformed actor references', () => {
    for (const altered of [
      { maxAmountWei: '0' },
      { maxAmountWei: '-1' },
      { maxAmountWei: '01' },
      { maxAmountWei: '1e18' },
      { maxAmountWei: '1'.repeat(79) },
      { chainId: '01' },
      { chainId: '18446744073709551616' },
      { executionWorkloadId: 'actor:forged' },
      { amountMode: 'MINIMUM' },
      { networkId: 'n'.repeat(48), chainId: '18446744073709551615' },
    ])
      expect(createNativeValueAuthorizationSchema.safeParse({ ...input, ...altered }).success).toBe(
        false,
      );
  });
});
