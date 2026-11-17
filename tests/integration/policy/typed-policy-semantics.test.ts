import { PolicyFactReader } from '../../../services/module-registry/src/domain/policy-facts.js';
import { generateKeyPairSync } from 'node:crypto';
import {
  compilePolicyArtifact,
  createPolicyArtifactCompilerSigner,
} from '../../../services/module-registry/src/domain/policy-artifact-compiler.js';
import {
  decodePolicyArtifactPayload,
  verifyPolicyArtifactCose,
} from '../../../services/module-registry/src/domain/policy-artifact.js';
import { describe, expect, it } from 'vitest';

import { pcCbor1 } from '../../../services/module-registry/src/domain/digest.js';
import { sha256 } from '../../../services/control-api/src/configuration/digest.js';
import {
  deploymentIntentCore,
  deploymentReservationCore,
} from '../../../services/control-api/src/configuration/deployment/intent-core.js';
import {
  deploymentDefinitionDigests,
  deploymentPolicyDefinitionSchema,
} from '../../../services/control-api/src/configuration/deployment/policy-contract.js';
import {
  compilePolicySemantics,
  simulateContractSemantics,
  validatePolicySemantics,
  policySemanticSchemaDigest,
  readActiveVisibilityDocument,
} from '../../../services/module-registry/src/domain/policy-semantics.js';

const participantId = '018f0000-0000-7000-8000-000000000101';
const privacyDomainId = '018f0000-0000-7000-8000-000000000201';
const contractMethodPolicyId = '018f0000-0000-7000-8000-000000000701';
const role = 'urn:openpc:role:018f0000-0000-7000-8000-000000000801';
const digest = `sha256:${'ab'.repeat(32)}`;
const rpc = {
  schemaVersion: '1.0.0',
  participantId,
  privacyDomainId,
  rules: [{ method: 'eth_call', effect: 'ALLOW', requiredRoles: [role] }],
};
const authored = {
  schemaVersion: '1.0.0',
  participantId,
  privacyDomainId,
  moduleBindings: [
    'pc.policy.rpc-surface',
    'pc.policy.contract-method',
    'pc.policy.argument-guard',
  ].map((moduleId) => ({
    moduleId,
    semanticVersion: '1.0.0',
    manifestDigest: digest,
    configurationDigest: digest,
  })),
  rpcPolicies: [rpc],
  contractPolicies: [{ contractMethodPolicyId, revision: '1' }],
  requiredFacts: [{ candidateId: 'fact', generationId: 'generation', factDigest: digest }],
};
it('does not infer active visibility from a legacy or unrelated policy and preserves typed corruption errors', () => {
  const legacy = pcCbor1({ schemaVersion: '1.0', assets: [], rootAssetIds: [] }).bytes;
  expect(() =>
    readActiveVisibilityDocument(legacy, Buffer.alloc(32, 1), contractMethodPolicyId),
  ).toThrow('PC-POLICY-2001');
  expect(() =>
    readActiveVisibilityDocument(legacy, policySemanticSchemaDigest(), contractMethodPolicyId),
  ).toThrow('PC-POLICY-2003');
  const typed = validatePolicySemantics(authored);
  expect(() =>
    readActiveVisibilityDocument(typed.bytes, policySemanticSchemaDigest(), contractMethodPolicyId),
  ).toThrow('PC-POLICY-2001');
});
const contract = {
  assetId: contractMethodPolicyId,
  runtimeBindingId: '018f0000-0000-7000-8000-000000000702',
  policyVersion: '1',
  tenantId: participantId,
  privacyDomainId,
  chainId: '31337',
  networkId: 'openpc-local',
  genesisDigest: digest,
  contractAddress: `0x${'11'.repeat(20)}`,
  proxyAddress: null,
  implementationAddress: null,
  codeDigest: digest,
  implementationCodeDigest: null,
  abiDigest: digest,
  canonicalSignature: 'transfer(address,uint256)',
  selector: '0xa9059cbb',
  canonicalAbi: [
    {
      type: 'function',
      name: 'transfer',
      inputs: [
        { name: 'to', type: 'address' },
        { name: 'amount', type: 'uint256' },
      ],
      outputs: [{ name: '', type: 'bool' }],
      stateMutability: 'nonpayable',
    },
  ],
  effect: 'READ',
  requiredRoles: [role],
  approvalRequirement: 'NONE',
  mfaRequirement: 'NONE',
  rpcMethodPolicyDigest: `sha256:${pcCbor1(rpc).digest.toString('hex')}`,
  nestedCallSetDigest: digest,
  namedSetCount: 0,
  rules: [{ parameterPath: 'inputs[1]', operandType: 'INTEGER', operator: 'LTE', values: ['100'] }],
};
const actor = {
  participantId,
  privacyDomainId,
  principalId: 'principal',
  assignmentId: 'assignment',
  roles: [role],
  authorityDigest: 'ab'.repeat(32),
};
const request = {
  contractMethodPolicyId,
  method: 'eth_call' as const,
  calldata: `0xa9059cbb${'00'.repeat(12)}${'22'.repeat(20)}${(99).toString(16).padStart(64, '0')}`,
};
const fact = {
  outcome: 'PRESENT',
  participantId,
  privacyDomainId,
  candidateId: 'fact',
  generationId: 'generation',
  factDigest: Array(32).fill(0xab),
  shardDigest: Array(32).fill(0xcd),
  observedAtMs: 1,
  snapshotAtMs: 2,
  freshUntilMs: 5,
};

// This exercises the real process adapter and sole evaluator. Full acceptance
// additionally requires database admission, identity and browser journey evidence.
describe('typed policy process boundary', () => {
  it('accepts standalone closed disclosure without dummy RPC, contract or Fact grants', () => {
    const document = {
      ...authored,
      rpcPolicies: [],
      contractPolicies: [],
      requiredFacts: [],
      moduleBindings: [
        { ...authored.moduleBindings[0]!, moduleId: 'pc.policy.selective-disclosure' },
      ],
      visibilityPolicies: [
        {
          policyId: '018f0000-0000-7000-8000-000000000901',
          selector: {
            kind: 'DISCLOSURE',
            profileId: '018f0000-0000-7000-8000-000000000950',
            profileDigest: digest,
            dataClassId: 'TRANSACTION',
          },
          mode: 'STATIC',
          effect: 'ALLOW',
          subject: { kind: 'PRINCIPAL', principalId: '018f0000-0000-7000-8000-000000000301' },
          purpose: 'AUDIT',
          requiredRoles: [role],
          dimensions: ['EXISTENCE', 'PAYLOAD'],
          fields: ['PEF-AMOUNT'],
          conditions: [],
        },
      ],
    };
    const validated = validatePolicySemantics(document);
    const key = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const signer = createPolicyArtifactCompilerSigner(
      key.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
    );
    const compilationInput = {
      participantId,
      privacyDomainId,
      policyId: '018f0000-0000-7000-8000-000000000920',
      semanticVersion: '1.0.0',
      semanticDocument: document,
    };
    const artifact = compilePolicyArtifact(compilationInput, signer);
    expect(artifact.semanticCbor).toEqual(validated.bytes);
    expect(decodePolicyArtifactPayload(artifact.payloadCbor).semanticDigest).toEqual(
      validated.digest,
    );
    expect(
      verifyPolicyArtifactCose([signer], artifact.payloadCbor, artifact.coseSign1),
    ).toBeDefined();
    expect(() =>
      compilePolicyArtifact(
        { ...compilationInput, participantId: '018f0000-0000-7000-8000-000000000999' },
        signer,
      ),
    ).toThrow();
    expect(() => signer.sign(Buffer.from('unbound bytes'))).toThrow();
    expect(validated.document.visibilityPolicies).toEqual(document.visibilityPolicies);
    expect(validatePolicySemantics([...validated.bytes], 'DECODE_SEMANTICS').bytes).toEqual(
      validated.bytes,
    );
    for (const amendment of [{ ready: true }, { fields: ['*'] }, { mode: 'DYNAMIC' }]) {
      const rejected = structuredClone(document);
      Object.assign(rejected.visibilityPolicies[0]!, amendment);
      expect(() => validatePolicySemantics(rejected)).toThrow('PC-POLICY-2003');
    }
    expect(() => validatePolicySemantics({ ...document, moduleBindings: [] })).toThrow(
      'PC-POLICY-2003',
    );
    const resource = {
      participantId,
      privacyDomainId,
      selector: validated.document.visibilityPolicies![0]!.selector,
      availableFields: ['PEF-AMOUNT'],
    };
    expect(() => compilePolicySemantics(validated.document, [], actor.principalId)).toThrow(
      'PC-POLICY-2003',
    );
    expect(() =>
      compilePolicySemantics(validated.document, [], actor.principalId, [], [], [resource]),
    ).not.toThrow();
    const disclosureActor = {
      ...actor,
      principalId: document.visibilityPolicies[0]!.subject.principalId,
    };
    const disclosureRequest = {
      visibilityPolicyId: document.visibilityPolicies[0]!.policyId,
      purpose: 'AUDIT',
      dimensions: ['PAYLOAD'] as const,
      fields: ['PEF-AMOUNT'],
    };
    expect(
      simulateContractSemantics(
        validated.document,
        [],
        disclosureActor,
        disclosureRequest,
        [],
        [],
        1,
        [],
        undefined,
        [resource],
      ).truthState,
    ).toBe('SUCCESS');
    expect(
      simulateContractSemantics(
        validated.document,
        [],
        disclosureActor,
        { ...disclosureRequest, purpose: 'MARKETING' },
        [],
        [],
        1,
        [],
        undefined,
        [resource],
      ).truthState,
    ).toBe('DENIED');
    const unchanged = validatePolicySemantics(authored);
    expect(unchanged.bytes).toEqual(pcCbor1(authored).bytes);
    expect(validatePolicySemantics({ ...authored, visibilityPolicies: [] }).bytes).toEqual(
      unchanged.bytes,
    );
  });

  it('preserves dedicated source rules and requires internal resolved inputs to compile', async () => {
    const sourceRpc = {
      ...rpc,
      rules: [{ method: 'eth_getBlockByNumber(false)', effect: 'ALLOW', requiredRoles: [role] }],
    };
    const source = {
      ...authored,
      contractPolicies: [],
      requiredFacts: [],
      rpcPolicies: [sourceRpc],
      moduleBindings: [
        ...authored.moduleBindings,
        {
          moduleId: 'pc.indexing.dedicated-policy',
          semanticVersion: '1.0.0',
          manifestDigest: digest,
          configurationDigest: digest,
        },
      ],
      indexerPolicies: [
        {
          schemaVersion: '1.0.0',
          participantId,
          privacyDomainId,
          workloadId: `urn:openpc:workload:${contractMethodPolicyId}`,
          indexerProfileId: contractMethodPolicyId,
          projectionPlanId: '018f0000-0000-7000-8000-000000000702',
          profileArtifactDigest: digest,
          planArtifactDigest: digest,
          acquisitionConfigurationDigest: digest,
          rpcPolicyDigest: `sha256:${pcCbor1(sourceRpc).digest.toString('hex')}`,
          rangeStart: '1',
          rangeEnd: '10',
          maximumRangeBlocks: '5',
          maximumResponseBytes: 4096,
          rules: [{ dataClass: 'BLOCK_HEADER', effect: 'ALLOW', requiredRoles: [role] }],
        },
      ],
    };
    const validated = validatePolicySemantics(source);
    expect(validated.document.indexerPolicies).toEqual(source.indexerPolicies);
    expect(await new PolicyFactReader('/not-an-executable').read(validated.document)).toEqual([]);
    expect(validatePolicySemantics([...validated.bytes], 'DECODE_SEMANTICS').digest).toEqual(
      validated.digest,
    );
    expect(() =>
      compilePolicySemantics(validated.document, [], source.indexerPolicies[0]!.workloadId),
    ).toThrow('PC-POLICY-2003');
    for (const amendment of [{ dataClass: 'FULL_BLOCK_TRANSACTIONS' }, { ready: true }]) {
      const rejected = structuredClone(source);
      Object.assign(rejected.indexerPolicies[0]!.rules[0]!, amendment);
      expect(() => validatePolicySemantics(rejected)).toThrow('PC-POLICY-2003');
    }
    const payload = {
      ...source,
      indexerInputs: [{ configurationCbor: [1], configurationDigest: digest.slice(7) }],
    };
    expect(() => validatePolicySemantics(payload)).toThrow('PC-POLICY-2003');
  });

  it('evaluates exact signed deployment inputs through the real process adapter', () => {
    // A signed external-wallet vector; the ephemeral key was discarded. No
    // wallet association, provider proof or runtime permission is inferred.
    const signedTransaction =
      '0x02f85e827a69090102830186a080808d6001600c60003960016000f300c001a076645ce5742da4093da606f82fdde171ea196fb1c6b133d83c118f05d6ef8b68a01e494cfed272b211acd4c2e3d82f932e042a63820f5f9ca2c6c5111df28777ad';
    const wrongChain =
      '0x02f85c01090102830186a080808d6001600c60003960016000f300c080a069c635cf82246f78bfb610f749c69efc68998cba06b309cefc775a68adedf3a6a0152896e1fc5f070f02aa02c7d4185c42ad2f18fe3da34169cec22dd30ea30b22';
    const deploymentPolicyId = '018f0000-0000-7000-8000-000000000703';
    const definition = deploymentPolicyDefinitionSchema.parse({
      schemaVersion: '1.0.0',
      profileId: 'reference:direct',
      profileVersion: '1.0.0',
      assuranceLevel: 'A0',
      creationEvidence: 'COMPLETE_SINGLE_CREATION_CALL_AND_OPCODE_V1',
      chainId: '31337',
      networkId: 'openpc-local',
      genesisDigest: digest,
      abiArtifactId: `urn:openpc:resource:${contractMethodPolicyId}`,
      artifact: {
        mode: 'EXACT_INIT_CODE',
        initCode: '0x6001600c60003960016000f300',
        runtimeCodeHash: '0xbc36789e7a1e281436464229828f817d6612f7b477d66591ff96a9e064bcc98a',
      },
      route: { mechanism: 'TRANSACTION_CREATE' },
      allowedSenders: ['0x6eb126907f1e1f7a35cd4307fe0dd73ceaf83be1'],
      requiredRoles: [role],
      approvalRequirement: 'NONE',
      webauthnRequired: false,
      expiresAt: '2030-01-01T00:00:00.000Z',
      transactionPolicy: {
        version: 1,
        allowedTransactionTypes: [2],
        maximumValue: `0x${'00'.repeat(32)}`,
        maximumGasLimit: '100000',
        maximumFeePerGas: `0x${'00'.repeat(31)}02`,
        maximumPriorityFeePerGas: `0x${'00'.repeat(31)}01`,
        maximumRawTransactionBytes: 131072,
        maximumCalldataBytes: 32768,
        maximumAccessListAddresses: 128,
        maximumAccessListStorageKeys: 1024,
      },
    });
    const publication = {
      deploymentPolicyId,
      participantId,
      privacyDomainId,
      definition,
      ...deploymentDefinitionDigests(definition),
      abiDigest: sha256(Buffer.from('[]')),
      publicationOperationId: '018f0000-0000-7000-8000-000000000704',
      publicationAuthorityDigest: digest,
      factoryBinding: null,
    };
    const signingPayload = '0x02db827a69090102830186a080808d6001600c60003960016000f300c0';
    const context = {
      intentId: '018f0000-0000-7000-8000-000000000705',
      participantId,
      privacyDomainId,
      participantEpoch: '18446744073709551615',
      actorSubjectId: 'principal:1',
      workloadBindingId: null,
      walletBindingId: 'wallet:1',
      walletBindingEpoch: '18446744073709551615',
      sender: Array.from(Buffer.from(definition.allowedSenders[0]!.slice(2), 'hex')),
      chainEnvironmentId: 'chain:31337',
      targetRuntimeId: '018f0000-0000-7000-8000-000000000301',
      policyGenerationDigest: digest.slice(7),
      authorityDigest: digest.slice(7),
      policyDecisionDigest: digest.slice(7),
      entitlementEnvelopeDigest: digest.slice(7),
      routingConstraintDigest: digest.slice(7),
      approvalSetDigest: sha256([]).slice(7),
      issuedAtMs: 1000,
      expiresAtMs: 2000,
    };
    const prepared = deploymentIntentCore('PREPARE_DEPLOYMENT_INTENT', {
      publication,
      signingPayload,
      context,
      nowMs: 1000,
    });
    expect(prepared.authority).toBe('NONE');
    expect(prepared.signingPayload).toBe(signingPayload);
    expect(prepared.sender).toBe(definition.allowedSenders[0]);
    expect(prepared.nonce).toBe('9');
    const reservation = {
      publication,
      recordBytes: prepared.recordBytes,
      signedTransaction,
      commandId: '018f0000-0000-7000-8000-000000000706',
      attemptId: '018f0000-0000-7000-8000-000000000707',
      nowMs: 1001,
    };
    expect(deploymentReservationCore(reservation)).toMatchObject({
      commandId: reservation.commandId,
      attemptId: reservation.attemptId,
      targetRuntimeId: `urn:openpc:resource:${context.targetRuntimeId}`,
      preparedRecordDigest: `sha256:${prepared.recordDigest}`,
      contractAddress: prepared.expectedContractAddress,
      senderAddress: prepared.sender,
      expiresAt: '1970-01-01T00:00:02.000Z',
    });
    for (const patch of [
      { commandId: 'caller-command' },
      { nowMs: 2000 },
      { signedTransaction: signingPayload },
      { ready: true },
    ])
      expect(() => deploymentReservationCore({ ...reservation, ...patch })).toThrow();
    // Inspect canonical bytes without lossy JSON-number conversion by the JS owner.
    expect(Buffer.from(prepared.intentBytes.slice(2), 'hex').toString('utf8')).toContain(
      '"participantEpoch":18446744073709551615',
    );
    expect(
      deploymentIntentCore('READ_DEPLOYMENT_INTENT', {
        publication,
        recordBytes: prepared.recordBytes,
      }),
    ).toEqual(prepared);
    for (const value of [
      { publication, signingPayload: signedTransaction, context, nowMs: 1000 },
      { publication, signingPayload, context: { ...context, ready: true }, nowMs: 1000 },
      { publication, signingPayload, context: { ...context, participantEpoch: 1 }, nowMs: 1000 },
      { publication, signingPayload, context, nowMs: 2000 },
    ])
      expect(() => deploymentIntentCore('PREPARE_DEPLOYMENT_INTENT', value)).toThrow();
    const { document } = validatePolicySemantics({
      ...authored,
      contractPolicies: [],
      deploymentPolicies: [{ deploymentPolicyId, definitionDigest: publication.definitionDigest }],
      moduleBindings: [
        'pc.policy.rpc-surface',
        'pc.policy.deployment',
        'pc.deployment.governance',
      ].map((moduleId) => ({
        moduleId,
        semanticVersion: '1.0.0',
        manifestDigest: digest,
        configurationDigest: digest,
      })),
      rpcPolicies: [
        {
          ...rpc,
          rules: [{ method: 'eth_sendRawTransaction', effect: 'ALLOW', requiredRoles: [role] }],
        },
      ],
    });
    const request = {
      deploymentPolicyId,
      method: 'eth_sendRawTransaction' as const,
      signedTransaction,
    };
    const result = simulateContractSemantics(
      document,
      [],
      actor,
      request,
      [fact],
      [publication],
      2,
    );
    expect(result.truthState).toBe('SUCCESS');
    expect(result.explanationCodes).toContain('TYPED_DEPLOYMENT_ALLOW');
    expect(
      simulateContractSemantics(
        document,
        [],
        actor,
        request,
        [{ ...fact, snapshotAtMs: 3 }],
        [publication],
        3,
      ),
    ).toEqual(result);
    expect(
      simulateContractSemantics(
        document,
        [],
        actor,
        { ...request, signedTransaction: wrongChain },
        [fact],
        [publication],
        3,
      ).truthState,
    ).toBe('DENIED');
    expect(
      simulateContractSemantics(
        document,
        [],
        actor,
        request,
        [{ ...fact, outcome: 'REORG' }],
        [publication],
        3,
      ).truthState,
    ).toBe('STALE');
  });
  it('authors independent status rules without accepting contract status simulation', () => {
    const status = {
      ...rpc,
      rules: [{ method: 'pc_getOperationStatus', effect: 'ALLOW', requiredRoles: [role] }],
    };
    const canonical = validatePolicySemantics({ ...authored, rpcPolicies: [rpc, status] });
    expect(validatePolicySemantics(Array.from(canonical.bytes), 'DECODE_SEMANTICS')).toEqual(
      canonical,
    );
    compilePolicySemantics(canonical.document, [contract], 'principal');
    expect(() =>
      simulateContractSemantics(
        canonical.document,
        [contract],
        actor,
        // Deliberate untrusted wire input; the process owner must reject it.
        { ...request, method: 'pc_getOperationStatus' as typeof request.method },
        [fact],
      ),
    ).toThrow('PC-POLICY-2003');
  });

  it('round trips exact typed semantic bytes and rejects caller authority fields', () => {
    const canonical = validatePolicySemantics(authored);
    expect(validatePolicySemantics(Array.from(canonical.bytes), 'DECODE_SEMANTICS')).toEqual(
      canonical,
    );
    expect(() =>
      validatePolicySemantics({ ...authored, contributions: [{ effect: 'ALLOW' }] }),
    ).toThrow('PC-POLICY-2003');
    expect(() =>
      compilePolicySemantics(
        canonical.document,
        [{ ...contract, policyVersion: '2' }],
        'principal',
      ),
    ).toThrow('PC-POLICY-2003');
    compilePolicySemantics(canonical.document, [contract], 'principal');
    expect(() =>
      compilePolicySemantics(
        canonical.document,
        [{ ...contract, runtimeBindingId: 'caller-selected-binding' }],
        'principal',
      ),
    ).toThrow('PC-POLICY-2003');
  });

  it('derives outcomes from method, roles, arguments and exact current fact state', () => {
    const document = validatePolicySemantics(authored).document;
    const first = simulateContractSemantics(document, [contract], actor, request, [fact]);
    expect(first.truthState).toBe('SUCCESS');
    const replay = simulateContractSemantics(document, [contract], actor, request, [
      { ...fact, snapshotAtMs: 3 },
    ]);
    expect(replay.resultDigest).toBe(first.resultDigest);
    expect(
      simulateContractSemantics(document, [contract], { ...actor, roles: [] }, request, [fact])
        .truthState,
    ).toBe('DENIED');
    expect(
      simulateContractSemantics(
        document,
        [contract],
        actor,
        { ...request, method: 'eth_sendRawTransaction' },
        [fact],
      ).truthState,
    ).toBe('DENIED');
    expect(
      simulateContractSemantics(
        document,
        [contract],
        actor,
        {
          ...request,
          calldata: `${request.calldata.slice(0, -64)}${(101).toString(16).padStart(64, '0')}`,
        },
        [fact],
      ).truthState,
    ).toBe('DENIED');
    expect(
      simulateContractSemantics(document, [contract], actor, request, [
        { ...fact, outcome: 'REORG' },
      ]).truthState,
    ).toBe('STALE');
    expect(simulateContractSemantics(document, [contract], actor, request, [null]).truthState).toBe(
      'PARTIAL',
    );
    expect(() =>
      simulateContractSemantics(document, [contract], actor, request, [
        { ...fact, privacyDomainId: 'foreign' },
      ]),
    ).toThrow('PC-POLICY-2003');
  });
});
