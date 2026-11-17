import { expect, it } from 'vitest';
import { transactionPolicySchema } from './transaction-policy.js';

it('requires exact monetary quantities and only narrows the reference profile', () => {
  const policy = {
    version: 1,
    allowedTransactionTypes: [0, 1, 2],
    maximumValue: `0x${'ff'.repeat(32)}`,
    maximumGasLimit: '18446744073709551615',
    maximumFeePerGas: `0x${'ff'.repeat(32)}`,
    maximumPriorityFeePerGas: `0x${'00'.repeat(32)}`,
    maximumRawTransactionBytes: 131072,
    maximumCalldataBytes: 32768,
    maximumAccessListAddresses: 128,
    maximumAccessListStorageKeys: 1024,
  };
  expect(transactionPolicySchema.parse(policy)).toEqual(policy);
  for (const mutation of [
    { maximumValue: 1 },
    { maximumValue: '0x1' },
    { maximumValue: `0x${'FF'.repeat(32)}` },
    { maximumGasLimit: 9007199254740992 },
    { maximumGasLimit: '18446744073709551616' },
    { maximumGasLimit: '01' },
    { maximumGasLimit: 'invalid' },
    { maximumGasLimit: '0' },
    { version: 2 },
    { allowedTransactionTypes: [0, 3] },
    { allowedTransactionTypes: [2, 1] },
    { allowedTransactionTypes: [1, 1] },
    { allowedTransactionTypes: [] },
    { maximumRawTransactionBytes: 131073 },
    { maximumCalldataBytes: 32769 },
    { maximumAccessListAddresses: 129 },
    { maximumAccessListStorageKeys: 1025 },
    { maximumFeePerGas: `0x${'00'.repeat(32)}`, maximumPriorityFeePerGas: `0x${'ff'.repeat(32)}` },
    { allowReplacement: true },
  ])
    expect(transactionPolicySchema.safeParse({ ...policy, ...mutation }).success).toBe(false);
});
