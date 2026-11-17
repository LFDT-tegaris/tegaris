import { describe, expect, it } from 'vitest';

import { rpcMethodCapabilities, rpcPolicyDocument } from './rpc-access';

describe('RPC access contract', () => {
  it('maps only the two governed RPC methods to runtime capabilities', () => {
    expect(rpcMethodCapabilities).toEqual({
      eth_call: 'CALL_RESULT_DISCLOSURE',
      eth_sendRawTransaction: 'SIGNED_TRANSACTION_SUBMISSION',
    });
    expect('eth_blockNumber' in rpcMethodCapabilities).toBe(false);
  });

  it('builds role-bound rules and exact contract references without duplicates', () => {
    const document = rpcPolicyDocument({
      participantId: '018f0000-0000-7000-8000-000000000101',
      privacyDomainId: '018f0000-0000-7000-8000-000000000201',
      roleId: 'urn:openpc:role:01a00000-0000-7000-8000-000000000001',
      methods: ['eth_call', 'eth_call', 'eth_sendRawTransaction'],
      moduleBindings: [
        {
          moduleId: 'pc.policy.runtime-guard',
          semanticVersion: '1.0.0',
          manifestDigest: 'sha256:' + '1'.repeat(64),
          configurationDigest: 'sha256:' + '2'.repeat(64),
        },
      ],
      contractPolicies: {
        eth_call: {
          contractMethodPolicyId: '01a00000-0000-7000-8000-000000000011',
          revision: '1',
        },
        eth_sendRawTransaction: {
          contractMethodPolicyId: '01a00000-0000-7000-8000-000000000012',
          revision: '1',
        },
      },
    });
    expect(document.rpcPolicies[0]?.rules).toEqual([
      {
        method: 'eth_call',
        effect: 'ALLOW',
        requiredRoles: ['urn:openpc:role:01a00000-0000-7000-8000-000000000001'],
      },
      {
        method: 'eth_sendRawTransaction',
        effect: 'ALLOW',
        requiredRoles: ['urn:openpc:role:01a00000-0000-7000-8000-000000000001'],
      },
    ]);
    expect(document.contractPolicies).toHaveLength(2);
  });

  it('keeps separate read and write RPC roles when only read contract operations are included', () => {
    const read = 'urn:openpc:role:01a00000-0000-7000-8000-000000000001';
    const write = 'urn:openpc:role:01a00000-0000-7000-8000-000000000002';
    const document = rpcPolicyDocument({
      participantId: '018f0000-0000-7000-8000-000000000101',
      privacyDomainId: '018f0000-0000-7000-8000-000000000201',
      roleId: read,
      rpcRoleIds: { eth_call: read, eth_sendRawTransaction: write },
      methods: ['eth_call'],
      moduleBindings: [],
      contractPolicies: {
        eth_call: { contractMethodPolicyId: '01a00000-0000-7000-8000-000000000011', revision: '1' },
        eth_sendRawTransaction: { contractMethodPolicyId: 'unused', revision: 'unused' },
      },
    });
    expect(document.rpcPolicies[0]?.rules).toEqual([
      { method: 'eth_call', effect: 'ALLOW', requiredRoles: [read] },
      { method: 'eth_sendRawTransaction', effect: 'ALLOW', requiredRoles: [write] },
    ]);
    expect(document.contractPolicies).toEqual([
      { contractMethodPolicyId: '01a00000-0000-7000-8000-000000000011', revision: '1' },
    ]);
  });
});
