import { describe, expect, it } from 'vitest';

import {
  assertArgumentRulesMatchAbi,
  assertAbiContainsFunction,
  canonicalAbiBytes,
  createAbiArtifactSchema,
  createArgumentRuleVersionSchema,
  createContractMethodPolicySchema,
  createRuntimeBindingSchema,
  selectorFor,
} from './contract-assets.js';
import { sha256 } from './digest.js';

const digest = (character: string) => `sha256:${character.repeat(64)}`;
const action = {
  actionIntentId: 'ACT-ABI_ARTIFACTS_CREATE_RESOURCE-V1',
  actionIntentDigest: digest('a'),
  reason: 'Import canonical ABI.',
};
const transferAbi = [
  {
    type: 'function',
    name: 'transfer',
    inputs: [
      { name: 'to', type: 'address' },
      { name: 'amount', type: 'uint256' },
    ],
    outputs: [{ name: 'accepted', type: 'bool' }],
    stateMutability: 'nonpayable',
  },
] as const;

describe('canonical ABI and contract-method admission', () => {
  it('rejects selector collisions in a complete ABI before policy selection', () => {
    const abi = [
      { ...transferAbi[0], name: 'burn', inputs: [{ name: 'amount', type: 'uint256' }] },
      {
        ...transferAbi[0],
        name: 'collate_propagate_storage',
        inputs: [{ name: 'value', type: 'bytes16' }],
      },
    ];
    expect(selectorFor('burn(uint256)')).toBe('0x42966c68');
    expect(selectorFor('collate_propagate_storage(bytes16)')).toBe('0x42966c68');
    const source = Buffer.from(JSON.stringify(abi));
    expect(
      createAbiArtifactSchema.safeParse({
        ...action,
        abi,
        sourceDocument: source.toString('base64'),
        provenance: {
          source: 'LOCAL_FIXTURE',
          locator: 'fixture://selector-collision',
          retrievedAt: '2026-09-12T00:00:00.000Z',
          sourceDigest: sha256(source),
        },
        abiDigest: sha256(canonicalAbiBytes(abi)),
      }).success,
    ).toBe(false);
    expect(() => assertAbiContainsFunction(abi, 'burn(uint256)')).toThrow('PC-FACT-4001');
    expect(() => assertAbiContainsFunction([abi[0]], 'burn(uint256)')).not.toThrow();
  });

  it('derives Ethereum selectors and canonical ABI identity', () => {
    expect(selectorFor('transfer(address,uint256)')).toBe('0xa9059cbb');
    expect(sha256(canonicalAbiBytes(transferAbi))).toBe(
      sha256(canonicalAbiBytes(JSON.parse(JSON.stringify(transferAbi)))),
    );
  });

  it('rejects malformed aliases, duplicate functions, and source-byte mismatch', () => {
    const sourceDocument = Buffer.from(JSON.stringify(transferAbi)).toString('base64');
    const valid = {
      ...action,
      abi: transferAbi,
      sourceDocument,
      provenance: {
        source: 'LOCAL_FIXTURE',
        locator: 'fixture://transfer',
        retrievedAt: '2026-09-10T00:00:00.000Z',
        sourceDigest: sha256(Buffer.from(JSON.stringify(transferAbi))),
      },
      abiDigest: sha256(canonicalAbiBytes(transferAbi)),
    };
    expect(createAbiArtifactSchema.safeParse(valid).success).toBe(true);
    expect(
      createAbiArtifactSchema.safeParse({
        ...valid,
        abi: [{ ...transferAbi[0], inputs: [{ name: 'amount', type: 'uint' }] }],
      }).success,
    ).toBe(false);
    expect(
      createAbiArtifactSchema.safeParse({ ...valid, abi: [...transferAbi, ...transferAbi] })
        .success,
    ).toBe(false);
    expect(createAbiArtifactSchema.safeParse({ ...valid, hidden: true }).success).toBe(false);
    expect(
      createAbiArtifactSchema.safeParse({
        ...valid,
        abi: [{ ...transferAbi[0], inputs: [{ name: 'amounts', type: 'uint256[0]' }] }],
      }).success,
    ).toBe(false);
    expect(
      createAbiArtifactSchema.safeParse({
        ...valid,
        abi: [
          {
            ...transferAbi[0],
            inputs: [{ name: 'empty', type: 'tuple', components: [] }],
          },
        ],
      }).success,
    ).toBe(false);
  });

  it('binds each rule operand to the selected ABI input without numeric coercion', () => {
    expect(() =>
      assertArgumentRulesMatchAbi(transferAbi, 'transfer(address,uint256)', [
        { parameterPath: 'inputs[0]', operandType: 'ADDRESS' },
        { parameterPath: 'inputs[1]', operandType: 'INTEGER' },
      ]),
    ).not.toThrow();
    expect(() =>
      assertArgumentRulesMatchAbi(transferAbi, 'transfer(address,uint256)', [
        { parameterPath: 'inputs[1]', operandType: 'ADDRESS' },
      ]),
    ).toThrow('PC-FACT-4001');
  });

  it('rejects rules that PDS cannot activate at the API owner boundary', () => {
    const boundedAbi = [
      {
        ...transferAbi[0],
        inputs: [
          { name: 'recipients', type: 'address[2]' },
          { name: 'amount', type: 'uint8' },
        ],
      },
    ];
    expect(() =>
      assertArgumentRulesMatchAbi(boundedAbi, 'transfer(address[2],uint8)', [
        {
          parameterPath: 'inputs[0].[0]',
          operandType: 'ADDRESS',
          operator: 'EQ',
          values: [`0x${'1'.repeat(40)}`],
        },
        {
          parameterPath: 'inputs[1]',
          operandType: 'INTEGER',
          operator: 'LTE',
          values: ['255'],
        },
      ]),
    ).not.toThrow();
    for (const rules of [
      [
        {
          parameterPath: 'inputs[0]',
          operandType: 'ADDRESS',
          operator: 'EQ',
          values: [`0x${'1'.repeat(40)}`],
        },
      ],
      [
        {
          parameterPath: 'inputs[0].[2]',
          operandType: 'ADDRESS',
          operator: 'EQ',
          values: [`0x${'1'.repeat(40)}`],
        },
      ],
      [
        {
          parameterPath: 'inputs[1]',
          operandType: 'INTEGER',
          operator: 'LTE',
          values: ['256'],
        },
      ],
      [
        {
          parameterPath: 'inputs[1]',
          operandType: 'INTEGER',
          operator: 'EQ',
          values: ['1', '2'],
        },
      ],
    ]) {
      expect(() =>
        assertArgumentRulesMatchAbi(boundedAbi, 'transfer(address[2],uint8)', rules),
      ).toThrow('PC-FACT-4001');
    }
  });

  it('rejects unresolved named sets and duplicate method scopes before durable activation', () => {
    const ruleInput = {
      ...action,
      actionIntentId: 'ACT-TYPED_ARGUMENT_RULE_VERSIONS_CREATE_RESOURCE-V1',
      runtimeBindingId: 'urn:openpc:resource:018f0000-0000-7000-8000-000000000301',
      abiArtifactId: 'urn:openpc:resource:018f0000-0000-7000-8000-000000000302',
      abiDigest: digest('b'),
      canonicalSignature: 'transfer(address,uint256)',
      version: '1.0.0',
      namedSetVersions: [
        {
          ownerId: 'urn:openpc:resource:018f0000-0000-7000-8000-000000000303',
          setId: 'treasury',
          version: '1.0.0',
          digest: digest('c'),
        },
      ],
      rules: [
        { parameterPath: 'inputs[1]', operandType: 'INTEGER', operator: 'LTE', values: ['1'] },
      ],
    };
    expect(createArgumentRuleVersionSchema.safeParse(ruleInput).success).toBe(false);

    const methodInput = {
      ...action,
      actionIntentId: 'ACT-CONTRACT_METHOD_POLICIES_CREATE_RESOURCE-V1',
      runtimeBindingId: ruleInput.runtimeBindingId,
      abiArtifactId: ruleInput.abiArtifactId,
      abiDigest: digest('b'),
      canonicalSignature: 'transfer(address,uint256)',
      selector: '0xa9059cbb',
      effect: 'WRITE',
      requiredRoles: ['writer', 'writer'],
      approvalRequirement: 'MAKER_CHECKER',
      mfaRequirement: 'WEBAUTHN',
      environments: ['LOCAL', 'LOCAL'],
      rpcMethodPolicyDigest: digest('c'),
      nestedCallSetDigest: digest('d'),
    };
    expect(createContractMethodPolicySchema.safeParse(methodInput).success).toBe(false);
  });

  it('rejects partial proxy bindings and cross-field extras', () => {
    const base = {
      ...action,
      actionIntentId: 'ACT-CONTRACT_RUNTIME_BINDINGS_CREATE_RESOURCE-V1',
      logicalContractId: 'urn:openpc:resource:018f0000-0000-7000-8000-000000000301',
      chainId: '1',
      networkId: 'mainnet',
      genesisDigest: digest('b'),
      contractAddress: `0x${'1'.repeat(40)}`,
      codeDigest: digest('c'),
      abiArtifactId: 'urn:openpc:resource:018f0000-0000-7000-8000-000000000302',
      abiDigest: digest('d'),
      abiVersion: '1.0.0',
    };
    expect(createRuntimeBindingSchema.safeParse(base).success).toBe(true);
    expect(
      createRuntimeBindingSchema.safeParse({
        ...base,
        resourceId: '018f0000-0000-7000-8000-000000000303',
      }).success,
    ).toBe(true);
    expect(
      createRuntimeBindingSchema.safeParse({
        ...base,
        resourceId: '018f0000-0000-4000-8000-000000000303',
      }).success,
    ).toBe(false);
    expect(
      createRuntimeBindingSchema.safeParse({ ...base, proxyAddress: `0x${'2'.repeat(40)}` })
        .success,
    ).toBe(false);
  });
});
