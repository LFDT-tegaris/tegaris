import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { join } from 'node:path';
const repo = process.cwd();
const { Pool } = createRequire(join(repo, 'package.json'))('pg');
const { pcCbor1 } = await import(join(repo, 'services/module-registry/src/domain/digest.ts'));
const { validatePolicySemantics, compilePolicySemantics } = await import(
  join(repo, 'services/module-registry/src/domain/policy-semantics.ts')
);
const root = process.argv[2];
assert.ok(root?.startsWith('/'));
const evidence = join(root, 'evidence/runtime-bootstrap');
const load = async (name) => JSON.parse(await readFile(join(evidence, name + '.json'), 'utf8'));
const participantId = '018f0000-0000-7000-8000-000000000101',
  privacyDomainId = '018f0000-0000-7000-8000-000000007201';
const pool = new Pool({
  host: '127.0.0.1',
  port: 55432,
  database: 'openpc_control',
  user: 'openpc_control',
  password: (await readFile(join(root, 'secrets/control_pg_password.txt'), 'utf8')).trim(),
  max: 1,
  options: '-c default_transaction_read_only=on',
});
try {
  const actors = await load('deployment-intent-actors');
  const actions = (
    await pool.query(
      "select action_intent_id from control.action_intent where resource_type='policy-sets' order by action_intent_id",
    )
  ).rows.map((row) => row.action_intent_id);
  assert.equal(actions.length, 3);
  let role;
  for (const actor of Object.values(actors)) {
    const source = await pool.query(
      "select role_id from control.assignment where participant_id=$1 and principal_id=$2 and privacy_domain_ids=$3 and state='ACTIVE' and 'ACT-POLICY_VERSIONS_CREATE_RESOURCE-V1'=any(action_intent_ids)",
      [participantId, actor.principalId, [privacyDomainId]],
    );
    assert.equal(source.rowCount, 1);
    role ??= source.rows[0].role_id;
    // The canonical initial actor already has these actions. A second fixture
    // assignment makes authority ambiguous and must never be manufactured here.
    const paths = await pool.query(
      `select required.action,count(a.assignment_id)::int count
       from unnest($4::text[]) required(action)
       left join control.assignment a on a.participant_id=$1 and a.principal_id=$2
         and a.state='ACTIVE' and a.valid_during @> clock_timestamp()
         and $3=any(a.privacy_domain_ids) and required.action=any(a.action_intent_ids)
       join control.authority_envelope e using(participant_id,authority_envelope_id)
       where e.state='ACTIVE' and $3=any(e.privacy_domain_ids)
         and required.action=any(e.action_intent_ids)
         and openpc.assignment_role_permits(a.participant_id,a.role_id,required.action)
       group by required.action order by required.action`,
      [participantId, actor.principalId, privacyDomainId, actions],
    );
    assert.deepEqual(
      paths.rows,
      actions.map((action) => ({ action, count: 1 })),
      'Each policy-set action requires exactly one initial authority path',
    );
  }
  const moduleBindings = (
    await pool.query(
      `select version.module_id as "moduleId",version.semantic_version as "semanticVersion",'sha256:'||encode(version.manifest_digest,'hex') as "manifestDigest",'sha256:'||encode(configuration.configuration_digest,'hex') as "configurationDigest" from control.module_installation installation join control.module_version version using(module_version_id) join control.module_configuration_generation configuration using(module_installation_id) where installation.participant_id=$1 and installation.privacy_domain_id=$2 and installation.state='ENABLED' and version.release_payload_cbor is not null and configuration.active=true order by version.module_id`,
      [participantId, privacyDomainId],
    )
  ).rows;
  assert.equal(moduleBindings.length, 15);
  const fixture = await load('source-configuration'),
    target = (await load('configuration-target')).resourceRef.slice(-36),
    indexer = (await load('configuration-indexer')).resourceRef.slice(-36),
    projection = (await load('configuration-projection')).resourceRef.slice(-36);
  const rpc = {
    schemaVersion: '1.0.0',
    participantId,
    privacyDomainId,
    rules: ['eth_call'].map((method) => ({ method, effect: 'ALLOW', requiredRoles: [role] })),
  };
  const acquisition = JSON.parse(
    await readFile(
      join(root, 'data/runtime-bootstrap/provider-probe-source/acquisition.json'),
      'utf8',
    ),
  );
  assert.equal(acquisition.runtime_target_id, target);
  const digest = (value) => 'sha256:' + pcCbor1(value).digest.toString('hex');
  const indexerPolicy = {
    schemaVersion: '1.0.0',
    participantId,
    privacyDomainId,
    workloadId: `urn:openpc:workload:${target}`,
    indexerProfileId: indexer,
    projectionPlanId: projection,
    profileArtifactDigest: fixture.indexerArtifactDigest,
    planArtifactDigest: fixture.projectionArtifactDigest,
    acquisitionConfigurationDigest: digest([
      'openpc:indexer-acquisition-configuration:v1',
      acquisition,
    ]),
    rpcPolicyDigest: digest(rpc),
    rangeStart: '10',
    rangeEnd: '10',
    maximumRangeBlocks: '1',
    maximumResponseBytes: 10000,
    rules: ['STATE_CALL'].map((dataClass) => ({
      dataClass,
      effect: 'ALLOW',
      requiredRoles: [role],
    })),
  };
  const semanticDocument = {
    schemaVersion: '1.0.0',
    participantId,
    privacyDomainId,
    moduleBindings,
    rpcPolicies: [rpc],
    contractPolicies: [],
    deploymentPolicies: [],
    indexerPolicies: [indexerPolicy],
    visibilityPolicies: [],
    requiredFacts: [],
  };
  const semantic = validatePolicySemantics(semanticDocument);

  compilePolicySemantics(
    semanticDocument,
    [],
    indexerPolicy.workloadId,
    [],
    [
      {
        configurationCbor: [...Buffer.from(fixture.configurationCborHex, 'hex')],
        configurationDigest: fixture.configurationDigest.slice(7),
      },
    ],
  );
  const input = {
    name: 'Initial governed source policy',
    participantId,
    privacyDomainId,
    semanticVersion: '1.0.0',
    semanticDocument,
    semanticDigest: 'sha256:' + semantic.digest.toString('hex'),
    sourceRequest: {
      indexerProfileId: indexer,
      projectionPlanId: projection,
      dataClass: 'STATE_CALL',
      rangeStart: '10',
      rangeEnd: '10',
      maximumResponseBytes: 10000,
    },
  };
  await writeFile(join(evidence, 'policy-set-input.json'), JSON.stringify(input), { mode: 0o600 });
  await writeFile(
    join(evidence, 'policy-set-compile-input.json'),
    JSON.stringify({
      command: 'COMPILE_SEMANTICS',
      value: {
        document: semanticDocument,
        admitted: [],
        workloadId: indexerPolicy.workloadId,
        deployments: [],
        indexerInputs: [
          {
            configurationCbor: [...Buffer.from(fixture.configurationCborHex, 'hex')],
            configurationDigest: fixture.configurationDigest.slice(7),
          },
        ],
        visibilityInputs: [],
      },
    }),
    { mode: 0o600 },
  );
  process.stdout.write(
    'OPENPC_POLICY_SET_INPUT|PASS|canonical-registry|unique-initial-authority|15-live-module-bindings|actual-qualified-source-bytes|real-core-semantics|compile-input-prepared|no-policy-business-write\n',
  );
} finally {
  await pool.end();
}
