import { expect, it } from 'vitest';
import { policyDocumentMaximumBytes, reviewPolicyDocument } from './policy-document-review';
const scope = {
  participantId: '018f0000-0000-7000-8000-000000000101',
  privacyDomainId: '018f0000-0000-7000-8000-000000000201',
};
const document = {
  schemaVersion: '1.0.0',
  ...scope,
  moduleBindings: [],
  contractPolicies: [],
  requiredFacts: [],
  rpcPolicies: [
    {
      schemaVersion: '1.0.0',
      ...scope,
      rules: [
        { method: 'eth_call', effect: 'ALLOW', requiredRoles: [] },
        { method: 'debug_traceTransaction', effect: 'DENY', requiredRoles: [] },
      ],
    },
  ],
};
it('reviews actual parsed counts and rules without claiming native admission', () => {
  const result = reviewPolicyDocument(JSON.stringify(document), scope);
  expect('error' in result).toBe(false);
  if ('error' in result) throw Error(result.error);
  expect(result.rpcRules).toEqual([
    { method: 'eth_call', effect: 'ALLOW' },
    { method: 'debug_traceTransaction', effect: 'DENY' },
  ]);
  expect(result.counts.find((v) => v.label === 'RPC policy groups')?.count).toBe(1);
});
it.each(['participantId', 'privacyDomainId'] as const)(
  'rejects foreign %s without echoing foreign details',
  (field) => {
    const foreign = { ...document, [field]: '018f0000-0000-7000-8000-000000000999' };
    expect(reviewPolicyDocument(JSON.stringify(foreign), scope)).toEqual({
      error: 'This policy file belongs to a different workspace.',
    });
  },
);
it('rejects nested foreign RPC scope and unknown top-level configuration', () => {
  expect(
    reviewPolicyDocument(
      JSON.stringify({
        ...document,
        rpcPolicies: [{ ...document.rpcPolicies[0], privacyDomainId: 'foreign' }],
      }),
      scope,
    ),
  ).toEqual({ error: 'The RPC rules must belong to the current workspace.' });
  expect(
    reviewPolicyDocument(JSON.stringify({ ...document, privateKey: 'not-a-real-key' }), scope),
  ).toEqual({
    error: 'Use a supported policy document without configuration or credential fields.',
  });
});
it.each(['{}', '[]', 'null', '{"broken":'])('rejects unreviewable input %s', (text) => {
  expect(reviewPolicyDocument(text, scope)).toHaveProperty('error');
});
it('bounds the full UTF-8 byte length and visible rules', () => {
  expect(reviewPolicyDocument('é'.repeat(policyDocumentMaximumBytes / 2 + 1), scope)).toEqual({
    error: 'The policy file must be no larger than 1 MiB.',
  });
  const result = reviewPolicyDocument(
    JSON.stringify({
      ...document,
      rpcPolicies: [
        {
          ...document.rpcPolicies[0],
          rules: Array.from({ length: 20 }, (_, i) => ({
            method: 'method' + i,
            effect: i % 2 ? 'DENY' : 'ALLOW',
          })),
        },
      ],
    }),
    scope,
  );
  if ('error' in result) throw Error(result.error);
  expect(result.rpcRuleCount).toBe(20);
  expect(result.rpcRules).toHaveLength(12);
});
