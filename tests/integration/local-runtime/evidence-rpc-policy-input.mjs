import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import {
  canonicalAbiBytes,
  createAbiArtifactSchema,
  createLogicalContractSchema,
  createRuntimeBindingSchema,
  createArgumentRuleVersionSchema,
  createContractMethodPolicySchema,
} from '../../../services/control-api/src/configuration/contract-assets.ts';
import { canonicalJson } from '../../../services/control-api/src/configuration/digest.ts';
import { uuidv7 } from '../../../services/control-api/src/configuration/governed-mutation-http.ts';
import { assignmentCreate } from '../../../services/participant-service/src/contracts/assignment.ts';
import { pcCbor1 } from '../../../services/module-registry/src/domain/digest.ts';

// Input preparation only: every asset and workload grant is created by its
// public owner. Retained inputs preserve the original business intent on retry.
const [mode, evidenceRoot, actionIntentDigest] = process.argv.slice(2);
const load = async (name) => JSON.parse(await readFile(join(evidenceRoot, name), 'utf8'));
const source = await load('policy-set-input.json');
const discovery = await load('discovery-credential-input.json');
const role = source.semanticDocument.rpcPolicies[0].rules[0].requiredRoles[0];
assert.equal(source.privacyDomainId, discovery.privacyDomainId);
assert.equal(source.participantId, discovery.participantId);
const hash = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const ref = async (name) => await load(`rpc-${name}-resource.json`);
const abi = [
  {
    type: 'function',
    name: 'balanceOf',
    inputs: [{ name: 'account', type: 'address' }],
    outputs: [{ name: '', type: 'uint256' }],
    stateMutability: 'view',
  },
];
const abiBytes = canonicalAbiBytes(abi);
const abiDigest = hash(abiBytes);
const definitions = {
  abi: ['ABI_ARTIFACTS', createAbiArtifactSchema],
  logical: ['LOGICAL_CONTRACT_ASSETS', createLogicalContractSchema],
  binding: ['CONTRACT_RUNTIME_BINDINGS', createRuntimeBindingSchema],
  rules: ['TYPED_ARGUMENT_RULE_VERSIONS', createArgumentRuleVersionSchema],
  method: ['CONTRACT_METHOD_POLICIES', createContractMethodPolicySchema],
};
let body, candidate;
if (mode === 'assignment') {
  const actors = await load('deployment-intent-actors.json');
  const binding = await ref('binding');
  const original = await load('rpc-assignment-input.json').catch((error) => {
    if (error.code !== 'ENOENT') throw error;
    return null;
  });
  const scope = {
    privacyDomainIds: [source.privacyDomainId],
    actionIntentIds: [],
    capabilityIds: ['CALL_RESULT_DISCLOSURE'],
    resourceIds: [binding.runtimeBindingId.slice(-36)],
    riskClasses: ['LOW'],
    makerCheckerRequired: false,
    stepUpRequired: false,
    onwardDelegationDepth: 0,
  };
  body = JSON.parse(
    JSON.stringify(
      assignmentCreate.parse({
        assignmentId: original?.body.assignmentId ?? uuidv7(),
        principalId: discovery.principalId,
        roleId: role,
        authorityEnvelopeId: actors.maker.readEnvelopeId,
        scopeDigest: hash(JSON.stringify(scope)),
        ...scope,
        validFrom: original?.body.validFrom ?? new Date().toISOString(),
        validUntil: '2030-01-01T00:00:00.000Z',
      }),
    ),
  );
  candidate = {
    id: body.assignmentId,
    participantId: source.participantId,
    state: 'ACTIVE',
    delegationEpoch: '0',
    ...body,
  };
} else {
  const definition = definitions[mode];
  assert.ok(definition, 'Known governed RPC configuration owner required');
  const base = {
    actionIntentId: `ACT-${definition[0]}_CREATE_RESOURCE-V1`,
    actionIntentDigest,
    reason: 'Authorize the isolated evidence journey balance read through public governance.',
  };
  if (mode === 'abi')
    body = {
      ...base,
      abi,
      sourceDocument: abiBytes.toString('base64'),
      abiDigest,
      provenance: {
        source: 'LOCAL_FIXTURE',
        locator: 'fixture://openpc-local/evidence-balance-read-v1',
        retrievedAt: '2026-09-22T00:00:00.000000Z',
        sourceDigest: abiDigest,
      },
    };
  if (mode === 'logical')
    body = { ...base, logicalName: 'evidence.balance', displayName: 'Evidence balance read' };
  if (mode === 'binding')
    body = {
      ...base,
      logicalContractId: (await ref('logical')).logicalContractId,
      chainId: '31337',
      networkId: 'openpc-local',
      genesisDigest: `sha256:${'11'.repeat(32)}`,
      contractAddress: process.env.OPENPC_RPC_READ_CONTRACT_ADDRESS,
      codeDigest: hash('local-contract-code'),
      abiArtifactId: (await ref('abi')).abiArtifactId,
      abiDigest,
      abiVersion: '1.0.0',
    };
  if (mode === 'rules' || mode === 'method') {
    const binding = await ref('binding');
    const shared = {
      ...base,
      runtimeBindingId: binding.runtimeBindingId,
      abiArtifactId: (await ref('abi')).abiArtifactId,
      abiDigest,
      canonicalSignature: 'balanceOf(address)',
    };
    if (mode === 'rules')
      body = {
        ...shared,
        version: '1.0.0',
        namedSetVersions: [],
        rules: [
          {
            parameterPath: 'inputs[0]',
            operandType: 'ADDRESS',
            operator: 'EQ',
            values: [`0x${'11'.repeat(20)}`],
          },
        ],
      };
    else
      body = {
        ...shared,
        selector: '0x70a08231',
        effect: 'READ',
        requiredRoles: [role],
        approvalRequirement: 'NONE',
        mfaRequirement: 'NONE',
        environments: ['LOCAL'],
        argumentRuleVersionId: (await ref('rules')).argumentRuleVersionId,
        rpcMethodPolicyDigest: `sha256:${pcCbor1(source.semanticDocument.rpcPolicies[0]).digest.toString('hex')}`,
        nestedCallSetDigest: hash(canonicalJson([])),
      };
  }
  body = definition[1].parse(body);
}
const value = candidate ? { body, candidate } : { body };
const path = join(evidenceRoot, `rpc-${mode}-input.json`);
try {
  await writeFile(path, JSON.stringify(value), { flag: 'wx', mode: 0o600 });
} catch (error) {
  if (error.code !== 'EEXIST') throw error;
  assert.deepEqual(await load(`rpc-${mode}-input.json`), value, 'Retained intent must stay exact');
}
process.stdout.write(`OPENPC_RPC_INPUT|PASS|${mode}|canonical-contract|immutable-intent\n`);
