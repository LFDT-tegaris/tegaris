import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { Pool } from 'pg';
import { canonicalJson, pcCbor1 } from '../../../services/module-registry/src/domain/digest.ts';
import { validatePolicySemantics } from '../../../services/module-registry/src/domain/policy-semantics.ts';

const participantId = '018f0000-0000-7000-8000-000000000101';
const privacyDomainId = '018f0000-0000-7000-8000-000000000201';
const policySetId = 'urn:openpc:policy-set:018f0000-0000-7000-8000-000000000920';
const readerRole = 'urn:openpc:role:018f0000-0000-7000-8000-000000000801';

/** Authored narrow grant input; only the public assignment owner can activate it. */
export function visibilityReadAssignment(binding, now = Date.now()) {
  assert.match(
    binding.runtimeBindingId,
    /^urn:openpc:resource:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
  );
  const resourceId = binding.runtimeBindingId.split(':').at(-1);
  return {
    assignmentId: resourceId,
    principalId: '018f0000-0000-7000-8000-000000000190',
    roleId: readerRole,
    authorityEnvelopeId: '018f0000-0000-7000-8000-000000000125',
    scopeDigest: `sha256:${'b7'.repeat(32)}`,
    privacyDomainIds: [privacyDomainId],
    actionIntentIds: ['ACT-RUNTIME_READ_RPC-V1'],
    capabilityIds: [],
    resourceIds: [resourceId],
    riskClasses: ['LOW'],
    validFrom: new Date(now - 30_000).toISOString(),
    validUntil: '2030-01-01T00:00:00.000Z',
    makerCheckerRequired: false,
    stepUpRequired: false,
    onwardDelegationDepth: 0,
  };
}

/** An anchored read keeps the source policy that made its Fact current. */
export function stateReadSourceCustody(previous, readMethod) {
  const source = previous?.semanticDocument;
  assert.ok(source, 'anchored state-read requires the current source policy');
  assert.ok(
    Array.isArray(source.indexerPolicies) && source.indexerPolicies.length > 0,
    'anchored state-read requires current indexer custody',
  );
  assert.ok(
    Array.isArray(source.rpcPolicies) && source.rpcPolicies.length > 0,
    'anchored state-read requires the source RPC policy',
  );
  const readPolicy = {
    schemaVersion: '1.0.0',
    participantId,
    privacyDomainId,
    rules: [{ method: 'eth_call', effect: 'ALLOW', requiredRoles: [readerRole] }],
  };
  assert.equal(
    `sha256:${pcCbor1(readPolicy).digest.toString('hex')}`,
    readMethod?.rpcMethodPolicyDigest,
    'anchored state-read RPC policy must match the configured contract-read digest',
  );
  const responsePolicy = {
    schemaVersion: '1.0.0',
    participantId,
    privacyDomainId,
    rules: ['eth_getLogs', 'eth_getTransactionByHash', 'eth_getTransactionReceipt'].map(
      (method) => ({ method, effect: 'ALLOW', requiredRoles: [readerRole] }),
    ),
  };
  const policies = new Map(
    [...source.rpcPolicies, readPolicy, responsePolicy].map((policy) => [
      canonicalJson(policy),
      policy,
    ]),
  );
  return {
    indexerPolicies: structuredClone(source.indexerPolicies),
    rpcPolicies: [...policies.keys()].sort().map((key) => structuredClone(policies.get(key))),
  };
}

/** Batch A has no Fact dependency. Anchored state reads require a current Fact
 * from supported acquisition and public admission, even for static visibility. */
export async function prepareVisibilityPolicy(
  root,
  evidence,
  browser = false,
  stateRead = false,
  outputName = browser ? 'typed-policy-browser-inputs.json' : 'typed-policy-inputs.json',
) {
  const load = async (name) => JSON.parse(await readFile(join(evidence, name), 'utf8'));
  const readMethod = stateRead
    ? await load('configuration-contract-read-resource.json')
    : undefined;
  const sourceCustody = stateRead
    ? stateReadSourceCustody(await load('typed-policy-inputs.json'), readMethod)
    : undefined;
  const pool = new Pool({
    host: '127.0.0.1',
    port: 55432,
    database: 'openpc_control',
    user: 'openpc_policy_runtime',
    max: 1,
    password: (await readFile(join(root, 'policy_runtime_db_password.txt'), 'utf8')).trim(),
  });
  let moduleBindings;
  const client = await pool.connect();
  try {
    await client.query('begin');
    await client.query(
      "select openpc.set_request_context('PARTICIPANT',$1,$2,uuidv7(),'ACT-POLICY_VERSIONS_CREATE_RESOURCE-V1',true)",
      [participantId, privacyDomainId],
    );
    moduleBindings = (
      await client.query(
        `select version.module_id as "moduleId",version.semantic_version as "semanticVersion",
      'sha256:'||encode(version.manifest_digest,'hex') as "manifestDigest",
      'sha256:'||encode(configuration.configuration_digest,'hex') as "configurationDigest"
      from control.module_installation installation join control.module_version version using(module_version_id)
      join control.module_configuration_generation configuration using(module_installation_id)
      where installation.participant_id=$1 and installation.privacy_domain_id=$2
        and installation.state='ENABLED' and version.release_payload_cbor is not null and configuration.active=true
      order by version.module_id`,
        [participantId, privacyDomainId],
      )
    ).rows;
    await client.query('rollback');
  } finally {
    client.release();
    await pool.end();
  }
  assert.equal(moduleBindings.length, 25);
  const binding = await load('configuration-contract-binding-resource.json');
  const principalId = '018f0000-0000-7000-8000-000000000111';
  const common = {
    mode: 'STATIC',
    effect: 'ALLOW',
    subject: { kind: 'PRINCIPAL', principalId },
    purpose: 'AUDIT',
    requiredRoles: [readerRole],
    conditions: [],
  };
  const id = (suffix) => `018f0000-0000-7000-8000-000000000${browser ? 'b' : 'a'}${suffix}`;
  const resource = {
    runtimeBindingId: binding.runtimeBindingId.split(':').at(-1),
    bindingRevision: binding.revision,
  };
  const visibilityPolicies = [
    {
      ...common,
      policyId: id('02'),
      selector: { kind: 'TRANSACTION', ...resource },
      dimensions: ['EXISTENCE', 'METADATA', 'PAYLOAD'],
      fields: ['from', 'to', 'value'],
    },
    {
      ...common,
      policyId: id('03'),
      selector: { kind: 'RECEIPT', ...resource },
      dimensions: ['EXISTENCE', 'METADATA', 'PAYLOAD'],
      fields: [],
    },
  ];
  const contractPolicies = readMethod
    ? [
        {
          contractMethodPolicyId: readMethod.contractMethodPolicyId.split(':').at(-1),
          revision: readMethod.revision,
        },
      ]
    : [];
  if (stateRead) {
    visibilityPolicies.splice(
      0,
      visibilityPolicies.length,
      {
        ...common,
        policyId: id('04'),
        purpose: 'STATE_READ',
        selector: { kind: 'STATE_READ', ...contractPolicies[0] },
        dimensions: ['EXISTENCE', 'METADATA', 'PAYLOAD'],
        fields: ['outputs[0]'],
      },
      {
        ...common,
        policyId: id('05'),
        purpose: browser ? 'STATE_READ' : 'EXPORT',
        subject: {
          kind: 'WORKLOAD',
          workloadId: 'urn:openpc:workload:018f0000-0000-7000-8000-000000000191',
        },
        selector: { kind: 'STATE_READ', ...contractPolicies[0] },
        dimensions: ['EXISTENCE', 'METADATA', 'PAYLOAD'],
        fields: ['outputs[0]'],
      },
    );
    for (const [index, kind, purpose, fields] of [
      ['06', 'TRANSACTION', 'TRANSACTION_READ', ['from', 'to', 'value']],
      ['07', 'RECEIPT', 'RECEIPT_READ', []],
      ['08', 'EVENT', 'EVENT_READ', ['inputs[0]']],
    ]) {
      visibilityPolicies.push({
        ...common,
        policyId: id(index),
        purpose: browser ? purpose : 'UNAUTHORIZED_PURPOSE',
        subject: {
          kind: 'WORKLOAD',
          workloadId: 'urn:openpc:workload:018f0000-0000-7000-8000-000000000191',
        },
        selector: {
          kind,
          ...resource,
          ...(kind === 'EVENT'
            ? {
                abiDigest: binding.abiDigest,
                eventSignature: 'Changed(uint256)',
              }
            : {}),
        },
        dimensions: ['EXISTENCE', 'METADATA', 'PAYLOAD'],
        fields,
      });
    }
  }
  const fact = stateRead ? await load('typed-policy-fact.json') : undefined;
  const document = {
    schemaVersion: '1.0.0',
    participantId,
    privacyDomainId,
    moduleBindings,
    rpcPolicies: sourceCustody?.rpcPolicies ?? [],
    contractPolicies,
    ...(sourceCustody ? { indexerPolicies: sourceCustody.indexerPolicies } : {}),
    requiredFacts: fact
      ? [
          {
            candidateId: fact.candidateId,
            generationId: fact.generationId,
            factDigest: `sha256:${Buffer.from(fact.factDigest).toString('hex')}`,
          },
        ]
      : [],
    visibilityPolicies,
  };
  const semantic = validatePolicySemantics(document);
  const input = {
    semanticVersion: stateRead
      ? process.env.OPENPC_VISIBILITY_RENEW_FACT === '1'
        ? browser
          ? `11.${2 * (Number(process.env.OPENPC_VISIBILITY_SOURCE_GENERATION ?? 3) - 2) + 1}.0`
          : `11.${2 * (Number(process.env.OPENPC_VISIBILITY_SOURCE_GENERATION ?? 3) - 2)}.0`
        : browser
          ? '11.1.0'
          : '11.0.0'
      : browser
        ? '10.1.0'
        : '10.0.0',
    ...(stateRead ? { workbenchPath: '/govern/visibility' } : {}),
    semanticDocument: document,
    semanticDigest: `sha256:${semantic.digest.toString('hex')}`,
    dependencyDigest: `sha256:${pcCbor1(moduleBindings).digest.toString('hex')}`,
    scopeDigest: `sha256:${createHash('sha256').update(canonicalJson({ participantId, privacyDomainId, policySetId })).digest('hex')}`,
    visibilityRequest: {
      visibilityPolicyId: visibilityPolicies[0].policyId,
      purpose: stateRead ? 'STATE_READ' : 'AUDIT',
      dimensions: stateRead ? ['EXISTENCE', 'METADATA', 'PAYLOAD'] : ['EXISTENCE', 'PAYLOAD'],
      fields: stateRead ? ['outputs[0]'] : ['from', 'to', 'value'],
    },
  };
  await writeFile(join(evidence, outputName), JSON.stringify(input));
}

export async function checkEffectiveVisibility(evidence, sessionToken, expected) {
  const input = JSON.parse(await readFile(join(evidence, 'typed-policy-inputs.json'), 'utf8'));
  for (const purpose of ['AUDIT', 'UNAUTHORIZED_PURPOSE']) {
    const query = new URLSearchParams({
      scopeDigest: input.scopeDigest,
      ...input.visibilityRequest,
      purpose,
      dimensions: input.visibilityRequest.dimensions.join(','),
      fields: input.visibilityRequest.fields.join(','),
    });
    const response = await fetch(`http://127.0.0.1:8080/api/v1/effective-access?${query}`, {
      headers: {
        'cookie': `__Host-openpc_session=${sessionToken}`,
        'openpc-api-version': '1',
        'openpc-participant-id': `urn:openpc:participant:${participantId}`,
        'openpc-privacy-domain-id': `urn:openpc:privacy-domain:${privacyDomainId}`,
      },
    });
    const body = await response.json();
    if (expected === 'UNAVAILABLE') {
      assert.equal(response.status, 404, JSON.stringify(body));
      continue;
    }
    assert.equal(response.status, 200, JSON.stringify(body));
    assert.equal(response.headers.get('cache-control'), 'no-store');
    assert.equal(body.authoritative, false);
    assert.equal(body.truthState, purpose === 'AUDIT' ? 'SUCCESS' : 'DENIED', JSON.stringify(body));
    assert.deepEqual(body.effects, purpose === 'AUDIT' ? ['ALLOW'] : ['DENY']);
  }
  process.stdout.write(
    `OPENPC_TYPED_VISIBILITY_EFFECTIVE|PASS|${expected}|purpose-denial|non-granting\n`,
  );
}
