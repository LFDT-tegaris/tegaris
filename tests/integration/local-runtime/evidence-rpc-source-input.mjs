import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { canonicalAbiBytes } from '../../../services/control-api/src/configuration/contract-assets.ts';
import { sha256 } from '../../../services/control-api/src/configuration/digest.ts';
import { localOperationId } from '../../../services/identity-service/src/domain/local-operation-id.ts';
import { pcCbor1 } from '../../../services/module-registry/src/domain/digest.ts';
import {
  validatePolicySemantics,
  compilePolicySemantics,
} from '../../../services/module-registry/src/domain/policy-semantics.ts';

// Only authored bytes. Qualification, publication, acquisition and admission
// must traverse their durable public/service owners after this input preflight.
const [mode, evidenceRoot, sourceRoot] = process.argv.slice(2);
const generation = Number(process.env.OPENPC_RPC_SOURCE_GENERATION ?? 2);
assert.ok(Number.isSafeInteger(generation) && generation >= 2);
const suffix = generation === 2 ? '' : `-${generation}`;
const prefix = `rpc-source${suffix}`;
const load = async (name) => JSON.parse(await readFile(join(evidenceRoot, name), 'utf8'));
const save = async (path, value) => {
  try {
    await writeFile(path, JSON.stringify(value), { flag: 'wx', mode: 0o444 });
  } catch (error) {
    if (error.code !== 'EEXIST') throw error;
    assert.deepEqual(JSON.parse(await readFile(path, 'utf8')), value, 'Source intent is immutable');
  }
};
const original = await load(
  generation === 2
    ? 'policy-set-input.json'
    : `rpc-source${generation === 3 ? '' : `-${generation - 1}`}-policy-input.json`,
);
let predecessorDigest = original.semanticDigest;
if (generation > 2 && mode === 'policy') {
  const previousRpc = `rpc-policy${generation === 3 ? '' : `-${generation - 1}`}`;
  const priorRpc = await load(`${previousRpc}-input.json`).catch((error) => {
    if (error.code !== 'ENOENT') throw error;
    return null;
  });
  const actors = await load('deployment-intent-actors.json');
  const { policySetId } = await load('policy-set-result.json');
  const response = await fetch(`http://127.0.0.1:8080/api/v1/policy-sets/${policySetId}`, {
    headers: {
      'Cookie': `__Host-openpc_session=${actors.maker.sessionToken}`,
      'OpenPC-API-Version': '1',
      'OpenPC-Participant-ID': `urn:openpc:participant:${original.participantId}`,
      'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${original.privacyDomainId}`,
      'X-Request-ID': localOperationId(),
      'X-Correlation-ID': localOperationId(),
    },
  });
  assert.equal(response.status, 200);
  const parent = await response.json();
  assert.equal(parent.policySetId, policySetId);
  assert.equal(parent.state, 'ACTIVE');
  assert.ok(
    [original.semanticDigest, priorRpc?.semanticDigest].includes(parent.activeVersionDigest),
  );
  predecessorDigest = parent.activeVersionDigest;
}
const discovery = await load('discovery-credential-input.json');
const binding = await load('rpc-binding-resource.json');
const abi = await load('rpc-abi-resource.json');
assert.equal(binding.contractAddress, process.env.OPENPC_RPC_READ_CONTRACT_ADDRESS);
assert.equal(binding.state, 'BOUND');
assert.equal(binding.abiArtifactId, abi.abiArtifactId);
if (mode === 'binding') {
  const value = {};
  for (const [output, input] of Object.entries({
    runtime_binding_id: 'runtimeBindingId',
    logical_contract_id: 'logicalContractId',
    chain_id: 'chainId',
    network_id: 'networkId',
    genesis_digest: 'genesisDigest',
    code_digest: 'codeDigest',
    contract_address: 'contractAddress',
    abi_digest: 'abiDigest',
    proxy_address: 'proxyAddress',
    implementation_address: 'implementationAddress',
    implementation_code_digest: 'implementationCodeDigest',
  }))
    value[output] = binding[input] ?? null;
  for (const key of ['runtime_binding_id', 'logical_contract_id'])
    value[key] = value[key].slice(-36);
  const bytes = canonicalAbiBytes(abi.canonicalAbi);
  assert.equal(sha256(bytes), binding.abiDigest);
  value.canonical_abi_hex = bytes.toString('hex');
  await save(join(sourceRoot, 'rpc-fact-binding.json'), value);
  await save(join(sourceRoot, 'rpc-fact-acquisition.json'), {
    runtime_target_id: discovery.targetId,
    request: {
      StateCall: {
        target_address: binding.contractAddress,
        calldata: `0x70a08231${'0'.repeat(24)}${'1'.repeat(40)}`,
      },
    },
    rate_limit: { window_ms: 60000, maximum_requests: 24 },
  });
} else if (mode === 'policy') {
  const fixture = await load(`${prefix}-configuration.json`);
  const acquisition = JSON.parse(
    await readFile(join(sourceRoot, 'rpc-fact-acquisition.json'), 'utf8'),
  );
  const role = original.semanticDocument.rpcPolicies[0].rules[0].requiredRoles[0];
  const rpc = {
    schemaVersion: '1.0.0',
    participantId: original.participantId,
    privacyDomainId: original.privacyDomainId,
    rules: ['eth_call', 'eth_getBlockByNumber(false)'].map((method) => ({
      method,
      effect: 'ALLOW',
      requiredRoles: [role],
    })),
  };
  const indexer = {
    ...original.semanticDocument.indexerPolicies[0],
    profileArtifactDigest: fixture.indexerArtifactDigest,
    planArtifactDigest: fixture.projectionArtifactDigest,
    acquisitionConfigurationDigest: `sha256:${pcCbor1(['openpc:indexer-acquisition-configuration:v1', acquisition]).digest.toString('hex')}`,
    rpcPolicyDigest: `sha256:${pcCbor1(rpc).digest.toString('hex')}`,
    rangeStart: '10',
    rangeEnd: '12',
    maximumRangeBlocks: '3',
    rules: ['STATE_CALL', 'BLOCK_HEADER'].map((dataClass) => ({
      dataClass,
      effect: 'ALLOW',
      requiredRoles: [role],
    })),
  };
  const semanticDocument = {
    ...original.semanticDocument,
    rpcPolicies: [rpc],
    indexerPolicies: [indexer],
  };
  assert.deepEqual(semanticDocument.contractPolicies, []);
  assert.deepEqual(semanticDocument.requiredFacts, []);
  const semantic = validatePolicySemantics(semanticDocument);
  compilePolicySemantics(
    semanticDocument,
    [],
    `urn:openpc:workload:${discovery.targetId}`,
    [],
    [
      {
        configurationCbor: [...Buffer.from(fixture.configurationCborHex, 'hex')],
        configurationDigest: fixture.configurationDigest.slice(7),
      },
    ],
  );
  await save(join(evidenceRoot, `${prefix}-policy-input.json`), {
    ...original,
    semanticVersion: `1.1.${generation - 2}`,
    semanticDocument,
    semanticDigest: `sha256:${semantic.digest.toString('hex')}`,
    predecessorDigest,
    policySetId: (await load('policy-set-result.json')).policySetId,
  });
} else throw new Error('Unsupported RPC source input phase');
process.stdout.write(
  `OPENPC_RPC_SOURCE_INPUT|PASS|${mode}|actual-bound-contract|no-business-effect\n`,
);
