// Inputs and independent response oracle for the acquired relationship journey.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, writeFile, rename } from 'node:fs/promises';
import { join } from 'node:path';
import { isoCBOR } from '@simplewebauthn/server/helpers';
import {
  canonicalAbiBytes,
  createAbiArtifactSchema,
  createLogicalContractSchema,
  createRuntimeBindingSchema,
} from '../../../services/control-api/src/configuration/contract-assets.ts';
import { pcCbor1 } from '../../../services/module-registry/src/domain/digest.ts';
import { validatePolicySemantics } from '../../../services/module-registry/src/domain/policy-semantics.ts';
import { prepareVisibilityPolicy } from './typed-visibility-policy.mjs';
import { assertRequestEvidence } from './visibility-response.mjs';

const entityTopic = `0x${'ab'.repeat(32)}`;
const participantId = '018f0000-0000-7000-8000-000000000101';
const privacyDomainId = '018f0000-0000-7000-8000-000000000201';
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');
const load = async (path) => JSON.parse(await readFile(path, 'utf8'));
const save = async (path, value) => {
  await writeFile(`${path}.next`, JSON.stringify(value), { mode: 0o600 });
  await rename(`${path}.next`, path);
};

export function relationshipAbiBody(actionIntentDigest) {
  const abi = [
    {
      type: 'function',
      name: 'balanceOf',
      stateMutability: 'view',
      inputs: [{ name: 'owner', type: 'address' }],
      outputs: [{ name: 'balance', type: 'uint256' }],
    },
    {
      type: 'event',
      name: 'RelationshipChanged',
      anonymous: false,
      inputs: [
        { name: 'entity', type: 'bytes32', indexed: true },
        { name: 'subject', type: 'bytes32', indexed: true },
        { name: 'transition', type: 'uint8', indexed: false },
        { name: 'from', type: 'uint64', indexed: false },
        { name: 'through', type: 'uint64', indexed: false },
      ],
    },
  ];
  const bytes = canonicalAbiBytes(abi);
  const abiDigest = `sha256:${digest(bytes)}`;
  return createAbiArtifactSchema.parse({
    actionIntentId: 'ACT-ABI_ARTIFACTS_CREATE_RESOURCE-V1',
    actionIntentDigest,
    reason: 'Import the controlled relationship event ABI.',
    abi,
    sourceDocument: bytes.toString('base64'),
    abiDigest,
    provenance: {
      source: 'LOCAL_FIXTURE',
      locator: 'fixture://openpc-local/relationship-v1',
      retrievedAt: '2026-09-21T00:00:00.000Z',
      sourceDigest: abiDigest,
    },
  });
}

export function relationshipCondition(fixture, fact) {
  const bytes = Buffer.from(fixture.configurationCborHex, 'hex');
  assert.equal(fixture.configurationDigest, `sha256:${digest(bytes)}`);
  const artifacts = isoCBOR.decodeFirst(bytes).get('resource_artifacts');
  const profiles = artifacts.filter(
    (artifact) => artifact.get('artifact_kind') === 'FactAdmissionProfile',
  );
  assert.equal(profiles.length, 1);
  const payload = Buffer.from(profiles[0].get('payload_cbor'));
  assert.equal(profiles[0].get('artifact_digest'), digest(payload));
  const profile = isoCBOR.decodeFirst(payload);
  assert.equal(profile.get('participantId'), participantId);
  assert.equal(profile.get('privacyDomainId'), privacyDomainId);
  return {
    kind: 'RELATIONSHIP',
    fact,
    factProfileId: profile.get('factProfileId'),
    profileDigest: digest(payload),
    namespace: 'local.relationship',
    entityKeyDigest: pcCbor1([
      'openpc:rgra-scoped-key:v1',
      participantId,
      privacyDomainId,
      'entity',
      Array.from(Buffer.from(entityTopic.slice(2), 'hex')),
    ]).digest.toString('hex'),
    relationshipKind: 'membership',
    rolePredicate: 'member',
    trustedSubjectSelector: 'WORKLOAD_UUID_V1',
  };
}

async function main() {
  const [mode, root, evidence, argument] = process.argv.slice(2);
  const read = (name) => load(join(evidence, name));
  let body;
  if (mode === 'abi-body') body = relationshipAbiBody(argument);
  else if (mode === 'logical-body')
    body = createLogicalContractSchema.parse({
      actionIntentId: 'ACT-LOGICAL_CONTRACT_ASSETS_CREATE_RESOURCE-V1',
      actionIntentDigest: argument,
      reason: 'Register the controlled relationship source.',
      logicalName: 'local.relationship',
      displayName: 'Local Relationship Source',
    });
  else if (mode === 'binding-body') {
    const abi = await read('relationship-abi-resource.json');
    const logicalContractId = (await read('relationship-logical-resource.json')).logicalContractId;
    body = createRuntimeBindingSchema.parse({
      actionIntentId: 'ACT-CONTRACT_RUNTIME_BINDINGS_CREATE_RESOURCE-V1',
      actionIntentDigest: argument,
      reason: 'Bind the registered relationship ABI to its external source.',
      logicalContractId,
      chainId: '31337',
      networkId: 'openpc-local',
      genesisDigest: `sha256:${'11'.repeat(32)}`,
      contractAddress: `0xa10a0000${logicalContractId.split(':').at(-1).replaceAll('-', '')}`,
      codeDigest: `sha256:${digest('local-contract-code')}`,
      abiArtifactId: abi.abiArtifactId,
      abiDigest: abi.abiDigest,
      abiVersion: '1.0.0',
    });
  } else if (mode === 'source') {
    const address = (await read('relationship-binding-resource.json')).contractAddress;
    const path = join(root, 'data/rpc-provider/fact-inputs.json');
    const previous = await load(path).catch((error) => {
      if (error.code === 'ENOENT') return {};
      throw error;
    });
    const opening = {
      block: 10,
      logIndex: process.env.OPENPC_RELATIONSHIP_PHASE === 'closing' ? 0 : 1,
      entityTopic,
      subjectTopic: `0x${'018f0000000070008000000000000191'.padStart(64, '0')}`,
      transition: 0,
      from: 10,
      through: null,
    };
    await save(path, {
      ...previous,
      relationshipContractAddress: address,
      relationshipEvents:
        process.env.OPENPC_RELATIONSHIP_PHASE === 'closing'
          ? [opening, { ...opening, logIndex: 2, transition: 1, through: 10 }]
          : [opening],
    });
  } else if (mode === 'policy') {
    await prepareVisibilityPolicy(
      join(root, 'secrets'),
      evidence,
      true,
      true,
      'typed-policy-inputs.json',
    );
    const input = await read('typed-policy-inputs.json');
    const policy = input.semanticDocument.visibilityPolicies.find(
      (entry) => entry.selector.kind === 'EVENT',
    );
    assert.ok(policy);
    input.semanticDocument.visibilityPolicies.push({
      ...structuredClone(policy),
      policyId: '018f0000-0000-7000-8000-000000000b09',
      mode: 'DYNAMIC',
      conditions: [
        relationshipCondition(
          await read('visibility-source-configuration.json'),
          input.semanticDocument.requiredFacts[0],
        ),
      ],
    });
    input.semanticVersion = `13.${process.env.OPENPC_VISIBILITY_SOURCE_GENERATION}.0`;
    input.semanticDigest = `sha256:${validatePolicySemantics(input.semanticDocument).digest.toString('hex')}`;
    await save(join(evidence, 'typed-policy-inputs.json'), input);
  } else if (mode === 'restart') {
    assert.deepEqual(
      await read('decisions-relationship-restarted.json'),
      await read('decisions-relationship-reorg.json'),
      'restart must preserve release custody without resending protected bytes',
    );
  } else if (mode === 'assert-response') {
    const variant = process.argv[6];
    assert.ok(['after', 'unresolved', 'closed'].includes(variant));
    const response = await readFile(join(evidence, `response-relationship-${variant}.json`));
    const value = JSON.parse(response);
    if (variant === 'unresolved') {
      assert.equal(argument, '502', response.toString());
      assert.equal(value.id, 32);
      assert.equal(value.error?.data?.pcCode, 'PC-RUNTIME-3009');
      assert.equal(
        value.result,
        undefined,
        'unknown earlier membership cannot fabricate empty absence',
      );
      assert.ok(
        (await read('typed-policy-fact.json')).freshUntilMs > Date.now(),
        'the original Fact must remain live during the ordering denial',
      );
      assertRequestEvidence(
        await read('decisions-before-relationship-unresolved.json'),
        await read('decisions-relationship-unresolved.json'),
        { forwarded: true, traceId: value.error?.data?.traceId },
      );
      process.stdout.write(
        'OPENPC_RELATIONSHIP_VISIBILITY|PASS|unresolved-earlier-occurrence|live-original-fact|no-protected-release\n',
      );
      return;
    }
    assert.equal(argument, '200', response.toString());
    assert.equal(value.id, variant === 'closed' ? 33 : 31);
    assert.equal(value.result.length, 1, 'the after-opening event must be released exactly once');
    assert.equal(value.result[0].logIndex, variant === 'closed' ? '0x1' : '0x2');
    assert.equal(value.result[0].data, `0x${'0'.repeat(63)}7`);
    assert.equal(value.result[0].removed, false);
    assert.doesNotMatch(response.toString(), /00000000000003e7/u, 'hidden event canary leaked');
    assertRequestEvidence(
      await read(`decisions-before-relationship-${variant}.json`),
      await read(`decisions-relationship-${variant}.json`),
      { responseDigest: digest(response) },
    );
    process.stdout.write(
      `OPENPC_RELATIONSHIP_VISIBILITY|PASS|public-source-and-fact|${variant === 'closed' ? 'static-allow-dynamic-deny|before-and-after-close' : 'after-opening-occurrence'}|one-release\n`,
    );
  } else throw new Error('unsupported relationship journey mode');
  if (body) process.stdout.write(JSON.stringify(body));
}

if (import.meta.main) await main();
