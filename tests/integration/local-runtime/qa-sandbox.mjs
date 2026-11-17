import assert from 'node:assert/strict';
import { constants as fsConstants } from 'node:fs';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { execFileSync, spawn } from 'node:child_process';
import {
  copyFile,
  lstat,
  readFile,
  realpath,
  writeFile,
  rename,
  readdir,
  readlink,
  rm,
} from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { localQaDurationMultiplier } from '../../../packages/security-kernel/src/local-qa-duration-profile.ts';
import { encodeCbor } from '../../../packages/security-kernel/src/canonical-cbor.ts';
import { verifyInstalledRuntimeSource } from './runtime-source-bootstrap.mjs';
import { localQaIssuer, qaPublicServices, qaIssuerFromCompose } from './qa-public-origin.mjs';
import {
  durationDigest,
  durationContainerState,
  durationExpectedState,
  durationTransitionPlan,
  completeDurationTransition,
  reconcileInitialDurationSave,
} from './qa-duration-transition.mjs';

export const qaRpcPlatformTrust = {
  platformContextId: '018f0000-0000-7000-8000-000000000401',
  initialBaseGenerationId: '018f0000-0000-7000-8000-000000000402',
  runtimeBindingId: '018f0000-0000-7000-8000-000000000301',
  targetProfileId: 'devnet-rpc-v1',
  environmentId: 'qa-rpc-platform-a',
};

export const qaParticipants = [
  {
    participantId: '018f0000-0000-7000-8000-000000000101',
    privacyDomainId: '018f0000-0000-7000-8000-000000000201',
    name: 'Local QA Participant A',
    people: [
      {
        hint: 'qa-a-maker',
        principalId: '018f0000-0000-7000-8000-000000000111',
        kind: 'PLATFORM_OPERATOR',
      },
      {
        hint: 'qa-a-checker',
        principalId: '018f0000-0000-7000-8000-000000000112',
        kind: 'PLATFORM_OPERATOR',
      },
    ],
  },
  {
    participantId: '018f0000-0000-7000-8000-000000000102',
    privacyDomainId: '018f0000-0000-7000-8000-000000000202',
    name: 'Local QA Participant B',
    people: [
      {
        hint: 'qa-b-maker',
        principalId: '018f0000-0000-7000-8000-000000000211',
        kind: 'PLATFORM_OPERATOR',
      },
      {
        hint: 'qa-b-checker',
        principalId: '018f0000-0000-7000-8000-000000000212',
        kind: 'PLATFORM_OPERATOR',
      },
    ],
  },
];
// Explicit administrative capabilities inside each own tenant. No Platform,
// runtime method authorization, policy result, approval or activation is seeded.
export const qaActions = [
  'ACT-IDENTITY_CREATE_SESSION-V1',
  'ACT-IDENTITY_DELETE_SESSION-V1',
  'ACT-IDENTITY_UPDATE_STEP_UP-V1',
  'ACT-PARTICIPANTS_READ_COLLECTION-V1',
  'ACT-PARTICIPANTS_READ_RESOURCE-V1',
  'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
  'ACT-PARTICIPANT_CREATE_MEMBER-V1',
  'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1',
  'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
  'ACT-POLICY_SETS_CREATE_RESOURCE-V1',
  'ACT-POLICY_SETS_READ_COLLECTION-V1',
  'ACT-POLICY_SETS_READ_RESOURCE-V1',
  'ACT-POLICY_VERSIONS_CREATE_RESOURCE-V1',
  'ACT-POLICY_VERSIONS_READ_COLLECTION-V1',
  'ACT-POLICY_VERSIONS_READ_RESOURCE-V1',
  'ACT-POLICY_CREATE_SIMULATION-V1',
  'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1',
  'ACT-APPROVAL_REQUESTS_READ_COLLECTION-V1',
  'ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1',
  'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1',
  'ACT-POLICY_APPROVE_REQUEST-V1',
  'ACT-PROVIDER_PROFILES_CREATE_RESOURCE-V1',
  'ACT-PROVIDER_PROFILES_READ_COLLECTION-V1',
  'ACT-PROVIDER_PROFILES_READ_RESOURCE-V1',
  'ACT-PROVIDER_PROFILES_UPDATE_RESOURCE-V1',
  'ACT-PROVIDER_APPROVE_QUALIFICATION-V1',
  'ACT-INDEXER_PROFILES_CREATE_RESOURCE-V1',
  'ACT-INDEXER_PROFILES_READ_RESOURCE-V1',
  'ACT-INDEXER_APPROVE_PROFILE-V1',
  'ACT-PROJECTION_PLANS_CREATE_RESOURCE-V1',
  'ACT-PROJECTION_PLANS_READ_RESOURCE-V1',
  'ACT-INDEXER_RECOVER_PLAN-V1',
  'ACT-RUNTIME_TARGETS_CREATE_RESOURCE-V1',
  'ACT-RUNTIME_TARGETS_READ_COLLECTION-V1',
  'ACT-RUNTIME_TARGETS_READ_RESOURCE-V1',
  'ACT-RUNTIME_TARGETS_UPDATE_RESOURCE-V1',
  'ACT-RUNTIME_TARGET_PROFILES_CREATE_RESOURCE-V1',
  'ACT-RUNTIME_TARGET_PROFILES_READ_RESOURCE-V1',
  'ACT-OPERATIONS_READ_OPERATION-V1',
  'ACT-RELEASE_BUNDLES_CREATE_RESOURCE-V1',
  'ACT-RELEASE_BUNDLES_READ_COLLECTION-V1',
  'ACT-RELEASE_BUNDLES_READ_RESOURCE-V1',
  'ACT-POLICY_ACTIVATE_PUBLISH-V1',
  'ACT-ACTIVATION_OCCURRENCES_CREATE_RESOURCE-V1',
  'ACT-ACTIVATION_OCCURRENCES_READ_COLLECTION-V1',
  'ACT-ACTIVATION_OCCURRENCES_READ_RESOURCE-V1',
  'ACT-POLICY_ACTIVATE_RELEASE-V1',
  'ACT-POLICY_ROLLBACK_RELEASE-V1',
  'ACT-MODULES_CREATE_RESOURCE-V1',
  'ACT-MODULES_READ_RESOURCE-V1',
  'ACT-MODULES_READ_COLLECTION-V1',
  'ACT-MODULE_CREATE_INSTALL-V1',
  'ACT-MODULE_ACTIVATE_RESOURCE-V1',
  'ACT-ABI_ARTIFACTS_CREATE_RESOURCE-V1',
  'ACT-ABI_ARTIFACTS_READ_RESOURCE-V1',
  'ACT-LOGICAL_CONTRACT_ASSETS_CREATE_RESOURCE-V1',
  'ACT-LOGICAL_CONTRACT_ASSETS_READ_RESOURCE-V1',
  'ACT-CONTRACT_RUNTIME_BINDINGS_CREATE_RESOURCE-V1',
  'ACT-CONTRACT_RUNTIME_BINDINGS_READ_RESOURCE-V1',
  'ACT-TYPED_ARGUMENT_RULE_VERSIONS_CREATE_RESOURCE-V1',
  'ACT-TYPED_ARGUMENT_RULE_VERSIONS_READ_RESOURCE-V1',
  'ACT-CONTRACT_METHOD_POLICIES_CREATE_RESOURCE-V1',
  'ACT-CONTRACT_METHOD_POLICIES_READ_RESOURCE-V1',
  'ACT-DEPLOYMENT_POLICIES_CREATE_RESOURCE-V1',
  'ACT-DEPLOYMENT_POLICIES_READ_RESOURCE-V1',
  'ACT-DEPLOYMENT_INTENTS_CREATE_RESOURCE-V1',
  'ACT-DEPLOYMENT_INTENTS_READ_RESOURCE-V1',
  'ACT-DEPLOYMENT_SUBMISSIONS_CREATE_RESOURCE-V1',
  'ACT-DEPLOYMENT_SUBMISSIONS_READ_RESOURCE-V1',
  'ACT-NATIVE_VALUE_AUTHORIZATIONS_CREATE_RESOURCE-V1',
  'ACT-NATIVE_VALUE_AUTHORIZATIONS_READ_RESOURCE-V1',
];
const emptyTables = [
  'participant',
  'privacy_domain',
  'principal',
  'identity_subject',
  'participant_membership',
  'credential',
  'session',
  'platform_context',
  'platform_envelope_scope',
  'authority_role',
  'authority_envelope',
  'assignment',
  'delegation',
  'operations_installation',
  'operations_generation_commit',
  'mutation_candidate',
  'approval_request',
  'mutation_evidence',
  'outbox_event',
  'policy',
  'policy_version',
  'policy_activation',
];
const docker = (...args) =>
  execFileSync('docker', args, {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: 180000,
  }).trim();
export async function qaRoot(root) {
  assert.equal(await realpath(root), root, 'QA root must be canonical');
  const stat = await lstat(root);
  assert.ok(
    stat.isDirectory() &&
      !stat.isSymbolicLink() &&
      stat.uid === process.getuid() &&
      (stat.mode & 0o777) === 0o700,
    'Private owned QA root required',
  );
  const marker = join(root, '.openpc-local-runtime-owner');
  assert.ok(!(await lstat(marker)).isSymbolicLink());
  const record = (await readFile(marker, 'utf8')).trim();
  assert.match(record, /^openpc-local-runtime:openpc-local-e2e-[a-f0-9]{12}:[a-f0-9]{64}$/u);
  const [, project, owner] = record.split(':');
  return { root, project, owner, record };
}
function optIn() {
  assert.equal(
    process.env.OPENPC_LOCAL_RUNTIME_QA_FIXTURE,
    '1',
    'Explicit local QA fixture opt-in required',
  );
}
// Duration settings are opt-in inputs; normal Compose intentionally has no profile key.
export function qaDurationComposeOverlay(repo, environment) {
  assert.equal(resolve(repo), repo);
  if (localQaDurationMultiplier(environment) === 1) return { services: {} };
  return {
    services: {
      ...Object.fromEntries(
        ['identity-service', 'admin-web', 'control-api', 'policy-service'].map((service) => [
          service,
          {
            environment: {
              OPENPC_LOCAL_RUNTIME: '1',
              OPENPC_LOCAL_RUNTIME_QA_FIXTURE: '1',
              OPENPC_LOCAL_QA_DURATION_PROFILE: 'LOCAL_QA_10X',
              ...(service === 'identity-service'
                ? {
                    IDENTITY_RECOVERY_LEASE_TTL_MS: '172800000',
                    IDENTITY_RECOVERY_ADMINISTRATOR_TTL_MS: '36000000',
                  }
                : {}),
            },
          },
        ]),
      ),
      envoy: {
        volumes: [
          {
            type: 'bind',
            source: join(repo, 'deploy/compose/local/envoy/local-gateway-qa-10x.yaml'),
            target: '/etc/envoy/envoy.yaml',
            read_only: true,
          },
        ],
      },
    },
  };
}
export function qaDurationEnvironment(ambient, retained, mode) {
  assert.ok(['NORMAL', 'LOCAL_QA_10X'].includes(mode));
  const value = { ...ambient, ...retained };
  delete value.OPENPC_LOCAL_QA_DURATION_PROFILE;
  if (mode === 'LOCAL_QA_10X') {
    value.OPENPC_LOCAL_QA_DURATION_PROFILE = mode;
    assert.equal(localQaDurationMultiplier(value), 10);
  }
  return value;
}
export function qaDurationRetainedContainers(retained, current, updated) {
  return retained.map(({ service }) => {
    const originals = current.filter((c) => c.service === service);
    const successors = updated.filter((c) => c.service === service);
    assert.equal(originals.length, 1, 'Missing or duplicate retained service');
    assert.ok(successors.length <= 1, 'Duplicate updated retained service');
    return successors[0] ?? originals[0];
  });
}
export function validateQaOidcBuild(containers, project, configuration) {
  assert.equal(containers.length, 1, 'Only the retained OIDC fixture may remain active');
  const c = containers[0];
  assert.equal(c.Config.Labels['com.docker.compose.project'], project);
  assert.equal(c.Config.Labels['com.docker.compose.service'], 'oidc-emulator');
  assert.equal(c.State.Running, true);
  assert.equal(c.State.Health?.Status, 'healthy');
  assert.equal(c.State.OOMKilled, false);
  assert.equal(
    c.Config.Image,
    'docker.io/library/node:24.19.0-alpine@sha256:2a49bdf71e9fd965a58c1703fd9ddd205b34e5782b692a72dd1d248abb0beb43',
  );
  assert.equal(c.HostConfig.Memory, GiB / 8);
  assert.ok([GiB / 8, GiB / 4].includes(c.HostConfig.MemorySwap));
  assert.equal(c.HostConfig.NanoCpus, 250_000_000);
  assert.equal(c.HostConfig.PidsLimit, 64);
  assert.equal(c.HostConfig.ReadonlyRootfs, true);
  assert.ok(c.HostConfig.SecurityOpt.includes('no-new-privileges:true'));
  for (const bindings of Object.values(c.HostConfig.PortBindings))
    for (const binding of bindings) assert.equal(binding.HostIp, '127.0.0.1');
  assert.deepEqual(c.Config.Cmd, ['node', '/app/server.mjs']);
  assert.deepEqual(
    mountView(c),
    qaComposeMounts(configuration, configuration.services['oidc-emulator']),
  );
}
export function validateQaRetainedFixture(fixture) {
  assert.equal(fixture.fixture, 'SYNTHETIC_INITIAL_IDENTITY_TRUST');
  assert.deepEqual(fixture.participants, qaParticipants);
  // Retained installations keep the capabilities granted at initialization.
  // Recognizing their metadata does not add later catalogue permissions.
  const prior = qaActions.filter((action) => action !== 'ACT-POLICY_VERSIONS_READ_COLLECTION-V1');
  const original = prior.filter((action) => action !== 'ACT-POLICY_ROLLBACK_RELEASE-V1');
  const expected = [original, prior, qaActions].find(
    (actions) => actions.length === fixture.actions.length,
  );
  assert.ok(expected, 'Unrecognized retained QA action catalogue');
  assert.deepEqual(fixture.actions, expected);
}
export function validateQaDurationConfiguration(before, after, repo, mode) {
  for (const name of ['identity-service', 'admin-web', 'control-api', 'policy-service'])
    assert.equal(
      before.services[name]?.environment?.OPENPC_LOCAL_QA_DURATION_PROFILE,
      undefined,
      'Prepared QA lineage has no authenticated normal baseline',
    );
  const expected = qaDurationComposeOverlay(
    repo,
    mode === 'LOCAL_QA_10X'
      ? {
          OPENPC_LOCAL_RUNTIME: '1',
          OPENPC_LOCAL_RUNTIME_QA_FIXTURE: '1',
          OPENPC_LOCAL_QA_DURATION_PROFILE: mode,
        }
      : {},
  );
  assert.deepEqual(Object.keys(before.services).sort(), Object.keys(after.services).sort());
  for (const [name, original] of Object.entries(before.services)) {
    const actual = after.services[name],
      planned = structuredClone(original);
    const overlay = expected.services[name];
    if (overlay?.environment)
      planned.environment = { ...planned.environment, ...overlay.environment };
    if (name === 'envoy' && mode === 'LOCAL_QA_10X') {
      planned.volumes = planned.volumes.map((v) =>
        v.target === '/etc/envoy/envoy.yaml' ? overlay.volumes[0] : v,
      );
    }
    assert.deepEqual(actual, planned, `Unrelated profile configuration drift: ${name}`);
    if (name === 'envoy') {
      const mounts = actual.volumes.filter((v) => v.target === '/etc/envoy/envoy.yaml');
      assert.equal(mounts.length, 1);
      assert.equal(mounts[0].type, 'bind');
      assert.equal(mounts[0].read_only, true);
      assert.equal(
        mounts[0].source,
        join(
          repo,
          'deploy/compose/local/envoy',
          mode === 'LOCAL_QA_10X' ? 'local-gateway-qa-10x.yaml' : 'local-gateway.yaml',
        ),
      );
    }
  }
  for (const key of Object.keys(before).filter((k) => k !== 'services'))
    assert.deepEqual(after[key], before[key]);
  assert.deepEqual(Object.keys(after).sort(), Object.keys(before).sort());
}
async function prepare(root) {
  optIn();
  const repo = resolve(dirname(new URL(import.meta.url).pathname), '../../..');
  const duration = qaDurationComposeOverlay(repo, process.env);
  const services = qaPublicServices(process.env.OPENPC_QA_PUBLIC_ORIGIN, duration.services);
  if (duration.services.envoy)
    assert.equal(
      await realpath(duration.services.envoy.volumes[0].source),
      duration.services.envoy.volumes[0].source,
    );
  const providerPin = process.env.OPENPC_PROVIDER_BOUNDED_QA_SOURCE_DIGEST;
  if (providerPin !== undefined && !/^sha256:[0-9a-f]{64}$/.test(providerPin))
    throw new Error('Invalid bounded QA provider digest');
  const ownership = await qaRoot(root);
  await writeFile(join(dirname(root), 'qa-root'), root + '\n', { mode: 0o600, flag: 'wx' });
  const accounts = Object.fromEntries(
    qaParticipants.flatMap((participant) =>
      participant.people.map((person) => [
        person.hint,
        {
          ...person,
          participantId: participant.participantId,
          password: randomBytes(24).toString('base64url'),
        },
      ]),
    ),
  );
  await writeFile(join(root, 'secrets/qa-accounts.json'), JSON.stringify(accounts), {
    mode: 0o400,
    flag: 'wx',
  });
  await writeFile(
    join(root, 'data/qa-compose.json'),
    JSON.stringify({
      services: {
        ...services,
        ...(process.env.OPENPC_LOCAL_QA_ROOTED_SOURCE === '1' || providerPin !== undefined
          ? {
              'control-worker': {
                ...(process.env.OPENPC_LOCAL_QA_ROOTED_SOURCE === '1'
                  ? { mem_limit: '256m', memswap_limit: '256m' }
                  : {}),
                ...(providerPin === undefined
                  ? {}
                  : { environment: { OPENPC_PROVIDER_BOUNDED_QA_SOURCE_DIGEST: providerPin } }),
              },
            }
          : {}),
        ...(providerPin === undefined
          ? {}
          : {
              'runtime-target': {
                environment: { OPENPC_PROVIDER_BOUNDED_QA_SOURCE_DIGEST: providerPin },
              },
            }),
        'control-migrate': { entrypoint: ['/bin/sh', '/local/migrate.sh', 'control-installation'] },
        'oidc-emulator': {
          environment: {
            ...services['oidc-emulator']?.environment,
            OIDC_EMULATOR_LOCAL_QA: '1',
            OIDC_EMULATOR_QA_ACCOUNTS_FILE: '/app/qa-accounts.json',
          },
          volumes: [`${root}/secrets/qa-accounts.json:/app/qa-accounts.json:ro`],
        },
      },
    }),
    { mode: 0o400, flag: 'wx' },
  );
  await writeFile(
    join(root, 'data/qa-ownership.json'),
    JSON.stringify({ version: 1, fixture: true, ...ownership }),
    { mode: 0o400, flag: 'wx' },
  );
}
async function seedQaParticipants(client, runtimeSourceSecretRoot) {
  await client.query('begin');
  try {
    await client.query(
      "select pg_advisory_xact_lock(hashtext('openpc-disposable-local-qa-fixture'))",
    );
    if (runtimeSourceSecretRoot) {
      try {
        await verifyInstalledRuntimeSource(
          client,
          runtimeSourceSecretRoot,
          qaParticipants[0].participantId,
          qaParticipants[0].privacyDomainId,
        );
      } catch {
        // Key comparisons may include private buffers in assertion diagnostics.
        // Retain the failing stage, without carrying the original error/cause.
        throw new Error('Runtime source initial trust verification failed');
      }
      for (const [table, id, expected] of [
        ['participant', 'participant_id', qaParticipants[0].participantId],
        ['privacy_domain', 'privacy_domain_id', qaParticipants[0].privacyDomainId],
      ]) {
        const rows = await client.query(`select ${id} id from control.${table}`);
        assert.deepEqual(
          rows.rows,
          [{ id: expected }],
          'Only the native installed initial scope is allowed',
        );
      }
    }
    for (const table of emptyTables) {
      if (runtimeSourceSecretRoot && ['participant', 'privacy_domain'].includes(table)) continue;
      const rows = await client.query(`select exists(select 1 from control.${table}) populated`);
      assert.equal(rows.rows[0].populated, false, 'QA fixture requires an empty installation');
    }
    const actions = await client.query(
      'select action_intent_id from control.action_intent where action_intent_id=any($1::text[])',
      [qaActions],
    );
    assert.equal(
      actions.rowCount,
      qaActions.length,
      'QA actions must exist in the immutable catalogue',
    );
    for (const participant of qaParticipants) {
      if (runtimeSourceSecretRoot && participant === qaParticipants[0]) continue;
      await client.query(
        "insert into control.participant(participant_id,display_name,state,authority_epoch) values($1,$2,'ACTIVE',1)",
        [participant.participantId, participant.name],
      );
      await client.query(
        "insert into control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state) values($1,$2,'Local QA only','PARTICIPANT_LOCAL','LOCAL_DEVELOPMENT','ACTIVE')",
        [participant.privacyDomainId, participant.participantId],
      );
      await client.query(
        'update control.participant set root_privacy_domain_id=$2 where participant_id=$1',
        [participant.participantId, participant.privacyDomainId],
      );
    }
    await client.query('commit');
  } catch (error) {
    await client.query('rollback');
    throw error;
  }
}

async function seedQaPrincipals(client, platformContextId = null, issuer = localQaIssuer) {
  await client.query('begin');
  try {
    await client.query(
      "select pg_advisory_xact_lock(hashtext('openpc-disposable-local-qa-fixture'))",
    );
    for (const participant of qaParticipants) {
      const pid = participant.participantId,
        privacy = participant.privacyDomainId;
      for (const person of participant.people) {
        const principal = person.principalId;
        await client.query(
          "insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch) values($1,$2,$3,$4,'ACTIVE',1)",
          [principal, pid, person.kind, `QA FIXTURE ${person.hint}`],
        );
        await client.query('insert into control.identity_subject(identity_subject_id) values($1)', [
          principal,
        ]);
        await client.query(
          'insert into control.participant_membership(membership_id,participant_id,identity_subject_id) values($1,$2,$1)',
          [principal, pid],
        );
        await client.query(
          "insert into control.credential(participant_id,principal_id,kind,issuer,subject,audience,state,credential_epoch,valid_from) values($1,$2,'OIDC_SUBJECT',$4,$3,'openpc-local-workbench','ACTIVE',1,clock_timestamp())",
          [pid, principal, principal, issuer],
        );
      }
      const administratorRole = await client.query(
        `with selected as (select uuidv7() id)
         insert into control.authority_role
          (authority_role_id,participant_id,role_id,display_name,action_intent_ids,origin,created_by_principal_id)
         select id,$1,'urn:openpc:role:'||id::text,'Synthetic local QA administrator',$2,
                'MIGRATED_ASSIGNMENT',$3 from selected
         returning role_id`,
        [pid, qaActions, participant.people[0].principalId],
      );
      assert.equal(administratorRole.rowCount, 1);
      const administratorRoleId = administratorRole.rows[0].role_id;
      for (const person of participant.people) {
        const principal = person.principalId,
          envelope = randomUUID(),
          assignment = randomUUID();
        // Existing LEGACY test-trust representation, deliberately synthetic.
        // These bytes are never described as a real genesis or governed grant proof.
        const semantic = encodeCbor([
            'SYNTHETIC_LOCAL_QA_TRUST',
            pid,
            privacy,
            principal,
            qaActions,
          ]),
          digest = createHash('sha256').update(semantic).digest(),
          cose = Buffer.from('d28440a04040', 'hex'),
          boundPlatformContext = pid === qaParticipants[0].participantId ? platformContextId : null;
        await client.query(
          `insert into control.authority_envelope(authority_envelope_id,participant_id,principal_id,maker_principal_id,checker_principal_id,
          authority_epoch,delegation_epoch,state,valid_from,semantic_cbor,semantic_digest,cose_sign1,privacy_domain_ids,action_intent_ids,resource_ids,risk_classes,maker_checker_required,step_up_required,onward_delegation_depth,platform_context_id,platform_authority_epoch)
          values($1,$2,$3,$4,$5,1,0,'ACTIVE',clock_timestamp(),$6,$7,$8,$9,$10,ARRAY['*'],ARRAY['LOW','STANDARD','HIGH'],true,true,0,$11,$12)`,
          [
            envelope,
            pid,
            principal,
            participant.people[0].principalId,
            participant.people[1].principalId,
            semantic,
            digest,
            cose,
            [privacy],
            qaActions,
            boundPlatformContext,
            boundPlatformContext ? '1' : null,
          ],
        );
        await client.query(
          `insert into control.assignment(assignment_id,participant_id,principal_id,authority_envelope_id,role_id,delegation_epoch,scope_digest,valid_during,state,created_by_principal_id,
          privacy_domain_ids,action_intent_ids,resource_ids,risk_classes,maker_checker_required,step_up_required,onward_delegation_depth)
          values($1,$2,$3,$4,$5,0,$6,tstzrange(clock_timestamp(),null,'[)'),'ACTIVE',$3,$7,$8,ARRAY['*'],ARRAY['LOW','STANDARD','HIGH'],true,true,0)`,
          [assignment, pid, principal, envelope, administratorRoleId, digest, [privacy], qaActions],
        );
      }
    }
    await client.query('commit');
  } catch (error) {
    await client.query('rollback');
    throw error;
  }
}

export async function seedQa(client, runtimeSourceSecretRoot) {
  await seedQaParticipants(client, runtimeSourceSecretRoot);
  await seedQaPrincipals(client);
}

async function providerRenewalTrust(root, input) {
  optIn();
  const ownership = await qaRoot(root);
  assert.equal(ownership.project, 'openpc-local-e2e-5c175f3d5afb');
  await maintenanceCustody(root);
  const manifest = JSON.parse(await readFile(join(root, 'data/qa-sandbox.json'), 'utf8'));
  assert.equal(manifest.fixture, true);
  assert.equal(manifest.project, ownership.project);
  const pg = manifest.containers.find((container) => container.service === 'control-pg');
  const actual = JSON.parse(docker('inspect', pg.id))[0];
  assert.equal(actual.State.Running, true);
  assert.equal(actual.Config.Labels['com.docker.compose.project'], ownership.project);
  assert.ok(actual.Mounts.some((mount) => mount.Source === join(root, 'data/control-pg')));
  assert.equal(JSON.parse(docker('inspect', serialBuilder))[0].State.Running, false);
  const { Pool } = await import('pg');
  const pool = new Pool({
    host: '127.0.0.1',
    port: 55432,
    database: 'openpc_control',
    user: 'openpc_control',
    max: 1,
    password: (await readFile(join(root, 'secrets/control_pg_password.txt'), 'utf8')).trim(),
  });
  const client = await pool.connect();
  try {
    const { supplementProviderRenewalTrust } = await import('./qa-provider-renewal-trust.mjs');
    process.stdout.write(
      JSON.stringify(await supplementProviderRenewalTrust(client, input)) + '\n',
    );
  } finally {
    client.release();
    await pool.end();
  }
}

function installQaRpcPlatformTrust(root) {
  return JSON.parse(
    execFileSync(
      process.execPath,
      ['--import', 'tsx', 'tests/integration/local-runtime/qa-platform-trust.ts', root],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'], timeout: 180000 },
    ),
  );
}

async function seed(root) {
  optIn();
  const ownership = await qaRoot(root),
    stored = JSON.parse(await readFile(join(root, 'data/qa-ownership.json'), 'utf8'));
  assert.equal(stored.record, ownership.record);
  const issuer = qaIssuerFromCompose(
    JSON.parse(await readFile(join(root, 'data/qa-compose.json'), 'utf8')),
  );
  const containers = JSON.parse(
    docker(
      'inspect',
      ...docker(
        'ps',
        '-q',
        '--filter',
        `label=com.docker.compose.project=${ownership.project}`,
        '--filter',
        'label=com.docker.compose.service=control-pg',
      ).split('\n'),
    ),
  );
  assert.equal(containers.length, 1);
  const container = containers[0];
  assert.ok(
    container.State.Running &&
      container.Mounts.some(
        (mount) =>
          mount.Source === join(root, 'data/control-pg') &&
          mount.Destination === '/var/lib/postgresql',
      ),
  );
  const { Pool } = await import('pg');
  const pool = new Pool({
    host: '127.0.0.1',
    port: 55432,
    database: 'openpc_control',
    user: 'openpc_control',
    password: (await readFile(join(root, 'secrets/control_pg_password.txt'), 'utf8')).trim(),
  });
  const client = await pool.connect();
  let platform;
  try {
    await seedQaParticipants(
      client,
      process.env.OPENPC_LOCAL_QA_ROOTED_SOURCE === '1' ? join(root, 'secrets') : undefined,
    );
    platform = installQaRpcPlatformTrust(root);
    await seedQaPrincipals(client, platform.platformContextId, issuer);
  } finally {
    client.release();
    await pool.end();
  }
  await writeFile(
    join(root, 'data/qa-fixture.json'),
    JSON.stringify({
      fixture: 'SYNTHETIC_INITIAL_IDENTITY_TRUST',
      participants: qaParticipants,
      actions: qaActions,
      rpcPlatformTrust: {
        ...qaRpcPlatformTrust,
        platformAuthorityEpoch: platform.platformAuthorityEpoch,
        platformAuthorityDigest: platform.platformAuthorityDigest,
      },
      excluded: [
        'configuration-generation',
        'participant-creation',
        'initial-invitation',
        'genesis-grant',
        'policy',
        'approval',
        'activation',
        'runtime-effects',
      ],
    }),
    { mode: 0o400, flag: 'wx' },
  );
}
async function retain(root, argv) {
  const ownership = await qaRoot(root),
    command = JSON.parse(argv);
  assert.ok(
    Array.isArray(command) &&
      command[0] === 'docker' &&
      command[1] === 'compose' &&
      command.includes(ownership.project),
  );
  const config = JSON.parse(docker(...command.slice(1), 'config', '--format', 'json'));
  for (const service of Object.values(config.services))
    for (const port of service.ports ?? [])
      assert.equal(port.host_ip, '127.0.0.1', 'QA ports must remain loopback only');
  const ids = docker(
    'ps',
    '-q',
    '--filter',
    `label=com.docker.compose.project=${ownership.project}`,
  )
    .split('\n')
    .filter(Boolean);
  const containers = JSON.parse(docker('inspect', ...ids));
  assert.ok(containers.every((item) => item.HostConfig.Memory > 0 && item.State.Running));
  await writeFile(
    join(root, 'data/qa-sandbox.json'),
    JSON.stringify({
      ...ownership,
      fixture: true,
      command,
      environment: Object.fromEntries(
        Object.entries(process.env).filter(([name]) => name.startsWith('OPENPC_LOCAL_')),
      ),
      containers: containers.map((item) => ({
        id: item.Id,
        image: item.Image,
        service: item.Config.Labels['com.docker.compose.service'],
      })),
    }),
    { mode: 0o600, flag: 'wx' },
  );
}
async function lifecycle(action, parent) {
  assert.equal(await realpath(parent), parent);
  const pointer = join(parent, 'qa-root');
  assert.ok(!(await lstat(pointer)).isSymbolicLink());
  const root = (await readFile(pointer, 'utf8')).trim(),
    owner = await qaRoot(root);
  assert.equal(dirname(root), parent);
  const manifest = JSON.parse(await readFile(join(root, 'data/qa-sandbox.json'), 'utf8'));
  assert.equal(manifest.record, owner.record);
  assert.equal(manifest.fixture, true);
  assert.ok(
    action === 'status' || !manifest.maintenance,
    'Finish the owned maintenance phase first',
  );
  const containers = JSON.parse(docker('inspect', ...manifest.containers.map((item) => item.id)));
  for (const item of containers) {
    const original = manifest.containers.find((entry) => entry.id === item.Id);
    assert.ok(
      original &&
        original.image === item.Image &&
        item.Config.Labels['com.docker.compose.project'] === owner.project,
    );
  }
  const order = [
      'control-pg',
      'fact-pg',
      'candidate-index-pg',
      'oidc-emulator',
      'signing-provider',
      'workload-issuer',
      'identity-service',
      'participant-service',
      'policy-service',
      'fact-service',
      'control-api',
      'control-worker',
      'admin-web',
      'envoy',
    ],
    migrationServices = new Set(['control-migrate', 'fact-migrate', 'candidate-index-migrate']),
    managedServices = new Set(order);
  assert.ok(
    containers.every((item) => {
      const service = item.Config.Labels['com.docker.compose.service'];
      return managedServices.has(service) || migrationServices.has(service);
    }),
  );
  if (action === 'stop') {
    docker(
      'stop',
      ...containers
        .filter((item) => managedServices.has(item.Config.Labels['com.docker.compose.service']))
        .map((item) => item.Id),
    );
  }
  if (action === 'start') {
    for (const service of order) {
      const item = containers.find(
        (entry) => entry.Config.Labels['com.docker.compose.service'] === service,
      );
      if (!item) continue;
      docker('start', item.Id);
      const deadline = Date.now() + 90000;
      while (true) {
        const state = JSON.parse(docker('inspect', item.Id))[0].State;
        if (state.Running && (!state.Health || state.Health.Status === 'healthy')) break;
        assert.ok(
          Date.now() < deadline && state.Running,
          'QA service is not ready; original state retained',
        );
        await new Promise((resolve) => setTimeout(resolve, 1000));
      }
    }
  }
  const current = JSON.parse(docker('inspect', ...containers.map((item) => item.Id)));
  process.stdout.write(
    JSON.stringify(
      {
        fixture: true,
        acceptance: 'UNVERIFIED',
        root,
        url: 'http://localhost:8080',
        accountsFile: join(root, 'secrets/qa-accounts.json'),
        contexts: qaParticipants,
        services: current.map((item) => ({
          service: item.Config.Labels['com.docker.compose.service'],
          running: item.State.Running,
          health: item.State.Health?.Status ?? null,
        })),
      },
      null,
      2,
    ) + '\n',
  );
}

const GiB = 1024 ** 3;
const maintenanceLog = (value) => process.stdout.write(`${value}\n`);
const serialBuilder = 'buildx_buildkit_openpc-r1-local-v1-node';
const serialBuilderImage =
  'moby/buildkit@sha256:28a898719c18a33f4e8000685287fa36fd0dd9560c6440227d3a732d79bb41d8';
const protectedServices = [
  'control-pg',
  'fact-pg',
  'candidate-index-pg',
  'identity-service',
  'oidc-emulator',
  'signing-provider',
  'workload-issuer',
];
const transactionServices = [
  'envoy',
  'admin-web',
  'control-api',
  'participant-service',
  'policy-service',
  'fact-service',
];
const maintenanceServices = [...protectedServices, ...transactionServices];
function qaMaintenanceServices(manifest) {
  const workers = manifest.containers.filter((c) => c.service === 'control-worker');
  assert.ok(workers.length <= 1, 'Duplicate QA worker');
  if (workers.length) assert.match(workers[0].image, /^sha256:[a-f0-9]{64}$/u);
  const services = workers.length
    ? [...maintenanceServices, 'control-worker']
    : maintenanceServices;
  assert.deepEqual(manifest.containers.map((c) => c.service).sort(), [...services].sort());
  assert.equal(new Set(manifest.containers.map((c) => c.id)).size, services.length);
  return services;
}
function validateQaWorker(container, expectedImage) {
  if (container.Config.Labels['com.docker.compose.service'] !== 'control-worker') return;
  assert.match(expectedImage, /^sha256:[a-f0-9]{64}$/u);
  assert.equal(container.Image, expectedImage);
  assert.equal(container.HostConfig.Memory, GiB / 4);
  assert.equal(container.HostConfig.MemorySwap, GiB / 4);
}

const mountView = (c) =>
  c.Mounts.map((m) => ({
    source: m.Source,
    target: m.Destination,
    type: m.Type,
    writable: m.RW,
  })).sort((a, b) => a.target.localeCompare(b.target));
const containerView = (c) => ({
  id: c.Id,
  image: c.Image,
  service: c.Config.Labels['com.docker.compose.service'],
  memory: c.HostConfig.Memory,
  swap: c.HostConfig.MemorySwap,
  mounts: mountView(c),
  startedAt: c.State.StartedAt,
});

export function validateQaMaintenanceContainers(manifest, containers, activeProjects, paused) {
  assert.equal(manifest.fixture, true);
  const services = qaMaintenanceServices(manifest);
  assert.equal(containers.length, services.length);
  assert.deepEqual(
    containers.map((c) => c.Config.Labels['com.docker.compose.service']).sort(),
    [...services].sort(),
  );
  assert.ok(
    activeProjects.every((p) => p === manifest.project),
    'Another active OpenPC project',
  );
  for (const c of containers) {
    validateQaWorker(c, manifest.containers.find((p) => p.service === 'control-worker')?.image);
    const prior = manifest.maintenance.baseline.find((p) => p.id === c.Id);
    const recorded = manifest.containers.find((p) => p.id === c.Id);
    assert.ok(prior && recorded, 'Unknown container');
    assert.equal(c.Image, recorded.image);
    assert.equal(c.Config.Labels['com.docker.compose.project'], manifest.project);
    assert.equal(prior.service, recorded.service);
    assert.equal(c.HostConfig.Memory, prior.memory);
    assert.ok(
      prior.memory > 0 &&
        Number.isFinite(prior.memory) &&
        Number.isFinite(prior.swap) &&
        prior.swap >= prior.memory,
      'Original finite memory and swap limits required',
    );
    assert.equal(c.HostConfig.MemorySwap, prior.swap);
    assert.deepEqual(mountView(c), prior.mounts);
    assert.equal(c.State.Running, !paused || protectedServices.includes(prior.service));
    if (protectedServices.includes(prior.service)) assert.equal(c.State.StartedAt, prior.startedAt);
  }
}
export function validateQaSerialBudget(
  hostKiB,
  externalKiB,
  retainedBytes,
  keeperBytes,
  builderBytes = 4 * GiB,
  browserBytes = 2 * GiB,
) {
  assert.ok(
    Number.isFinite(hostKiB) && hostKiB >= (1.5 * GiB) / 1024 && hostKiB <= (2 * GiB) / 1024,
    'Bounded QA host cap must be 1.5–2 GiB',
  );
  assert.equal(builderBytes, 4 * GiB);
  assert.equal(browserBytes, 2 * GiB);
  assert.ok(
    retainedBytes + (keeperBytes * 256) / 320 + builderBytes <= 8 * GiB,
    'Aggregate service cap exceeds 8 GiB',
  );
  assert.ok(
    externalKiB * 1024 >= retainedBytes + keeperBytes + builderBytes + browserBytes,
    'Incomplete external reservation',
  );
}
export function validateQaBuilder(container, memoryBytes, running) {
  assert.equal(container.Name, '/' + serialBuilder);
  assert.equal(container.Config.Image, serialBuilderImage);
  assert.ok(container.Config.Env.includes('OPENPC_BUILDER_OWNER=openpc-r1-local-runtime-v1'));
  assert.equal(container.HostConfig.Memory, memoryBytes);
  assert.equal(container.HostConfig.MemorySwap, memoryBytes);
  assert.equal(container.HostConfig.CpuPeriod, 100000);
  assert.equal(container.HostConfig.CpuQuota, 200000);
  assert.equal(container.State.Running, running);
  assert.equal(container.Mounts.length, 1);
  assert.ok(
    container.Mounts.some(
      (m) =>
        m.Type === 'volume' &&
        m.Name === serialBuilder + '_state' &&
        m.Destination === '/var/lib/buildkit',
    ),
  );
}
export function validateQaExecutor(builderPath, executorPath, maximum, swap) {
  assert.ok(builderPath.startsWith('/') && builderPath !== '/' && !builderPath.includes('..'));
  assert.ok(
    executorPath === builderPath || executorPath.startsWith(builderPath + '/'),
    'Executor escaped the builder cgroup',
  );
  assert.equal(String(maximum), String(4 * GiB));
  assert.equal(String(swap), '0');
}
export function qaPressureRejected(availableKiB, fullAvg10, oomCount, initialOom) {
  return (
    !Number.isFinite(availableKiB) ||
    availableKiB < 1024 * 1024 ||
    !Number.isFinite(fullAvg10) ||
    fullAvg10 >= 1 ||
    !Number.isFinite(oomCount) ||
    !Number.isFinite(initialOom) ||
    oomCount > initialOom
  );
}
export function validateQaComposeCommand(command, root, repo, project) {
  assert.ok(Array.isArray(command));
  assert.deepEqual(command.slice(0, 2), ['docker', 'compose']);
  const projects = [],
    files = [];
  for (let i = 2; i < command.length; i += 2) {
    const [flag, value] = command.slice(i, i + 2);
    assert.ok(typeof value === 'string' && !/[\n\0]/.test(value));
    if (['-p', '--project-name'].includes(flag)) projects.push(value);
    else {
      assert.ok(['-f', '--file'].includes(flag));
      assert.ok(
        value === join(repo, 'deploy/compose/local/compose.yaml') ||
          (value.startsWith(root + '/data/') && resolve(value) === value),
      );
      files.push(value);
    }
  }
  assert.deepEqual(projects, [project]);
  assert.ok(files.includes(join(repo, 'deploy/compose/local/compose.yaml')));
  assert.equal(files.length, new Set(files).size);
}
async function maintenanceDocument(root) {
  const owner = await qaRoot(root),
    path = join(root, 'data/qa-sandbox.json');
  const info = await lstat(path);
  assert.ok(!info.isSymbolicLink() && info.uid === process.getuid() && (info.mode & 0o077) === 0);
  const manifest = JSON.parse(await readFile(path, 'utf8'));
  assert.equal(manifest.record, owner.record);
  assert.equal(manifest.project, owner.project);
  assert.equal(manifest.root, root);
  assert.equal(manifest.fixture, true);
  qaMaintenanceServices(manifest);
  const repo = resolve(dirname(new URL(import.meta.url).pathname), '../../..');
  validateQaComposeCommand(manifest.command, root, repo, owner.project);
  for (let i = 2; i < manifest.command.length; i += 2)
    if (['-f', '--file'].includes(manifest.command[i]))
      assert.equal(await realpath(manifest.command[i + 1]), manifest.command[i + 1]);
  const fixture = JSON.parse(await readFile(join(root, 'data/qa-fixture.json'), 'utf8'));
  validateQaRetainedFixture(fixture);
  return manifest;
}
async function saveMaintenance(root, manifest) {
  const target = join(root, 'data/qa-sandbox.json'),
    temporary = target + '.maintenance-tmp';
  await writeFile(temporary, JSON.stringify(manifest), { mode: 0o600, flag: 'wx' });
  await rename(temporary, target);
}
async function maintenanceLocks(root, host, external, peak = 40) {
  const repo = resolve(dirname(new URL(import.meta.url).pathname), '../../..');
  const canonical = dirname(
    execFileSync('git', ['rev-parse', '--path-format=absolute', '--git-common-dir'], {
      encoding: 'utf8',
    }).trim(),
  );
  execFileSync(
    'bash',
    [
      join(canonical, 'scripts/maintenance/run-bounded.sh'),
      '--memory-gib',
      String(host),
      '--external-memory-gib',
      String(external),
      '--peak-disk-gib',
      String(peak),
      '--reuse',
      '--',
      'true',
    ],
    { stdio: 'inherit' },
  );
  await maintenanceCustody(root);
  return repo;
}
async function maintenanceCustody(root) {
  const canonical = dirname(
    execFileSync('git', ['rev-parse', '--path-format=absolute', '--git-common-dir'], {
      encoding: 'utf8',
    }).trim(),
  );
  execFileSync(
    'bash',
    [
      '-c',
      'source "$1/scripts/maintenance/local-runtime-images.sh"; openpc_require_heavy_lock',
      '--',
      canonical,
    ],
    { stdio: 'inherit' },
  );
  const owner = Number(process.env.OPENPC_RUNTIME_OWNER_PID);
  assert.ok(Number.isSafeInteger(owner) && owner > 1);
  let pid = process.pid;
  while (pid > 1 && pid !== owner)
    pid = Number(/^PPid:\s+(\d+)/m.exec(await readFile(`/proc/${pid}/status`, 'utf8'))?.[1]);
  assert.equal(pid, owner);
  assert.equal(await readlink(`/proc/${owner}/fd/8`), join(root, '.openpc-local-runtime-owner'));
  const lock = spawn('flock', ['-n', join(root, '.openpc-local-runtime-owner'), 'true'], {
    stdio: 'ignore',
  });
  assert.equal(
    await new Promise((resolve) => lock.once('exit', resolve)),
    1,
    'Live QA root lock required',
  );
}
const authSnapshot = (manifest) => {
  const pg = manifest.containers.find((c) => c.service === 'control-pg');
  const auth = JSON.parse(
    docker(
      'exec',
      pg.id,
      'psql',
      '-X',
      '-At',
      '-U',
      'openpc_control',
      '-d',
      'openpc_control',
      '-c',
      `select json_build_object('sessions',(select coalesce(json_agg(s order by s.session_id),'[]') from (select session_id,principal_id,participant_id,privacy_domain_id,context_mode,session_epoch,state,authority_epoch,participant_epoch,delegation_epoch from control.session) s),'credentials',(select coalesce(json_agg(c order by c.credential_id),'[]') from (select credential_id,principal_id,participant_id,state,credential_epoch,authenticator_sign_count from control.credential where kind='WEBAUTHN') c),'policyRecords',(select coalesce(json_agg(p order by p.policy_id),'[]') from control.policy p),'policyVersionCount',(select count(*) from control.policy_version),'policyGenerationCount',(select count(*) from control.policy_generation),'effects',json_build_object('providers',(select count(*) from control.provider_profile),'targets',(select count(*) from control.runtime_target),'wallets',(select count(*) from control.wallet_binding),'policies',(select count(*) from control.policy),'approvals',(select count(*) from control.approval_request),'candidates',(select count(*) from control.mutation_candidate)));`,
    ),
  );
  // Exact retained row preservation across additive migration and the authorized
  // Identity process refresh. Only aggregate digests enter the private manifest.
  const tables = [
    'principal',
    'participant',
    'privacy_domain',
    'participant_membership',
    'credential',
    'session',
    'authority_envelope',
    'assignment',
    'approval_request',
    'approval_decision_record',
    'mutation_candidate',
    'idempotency_record',
    'mutation_evidence',
    'abi_artifact',
    'logical_contract_asset',
    'policy',
    'policy_version',
    'policy_generation',
    'provider_profile',
    'runtime_target',
    'wallet_binding',
    'outbox_aggregate_head',
    'outbox_event',
    'business_outbox_head',
    'audit_occurrence',
    'configuration_work',
    'work_item',
    'mfa_challenge',
    'platform_recovery_enrollment',
    'platform_recovery_case',
    'platform_recovery_challenge',
    'platform_recovery_proof',
    'platform_envelope_scope',
    'platform_envelope_scope_successor',
    'platform_scope_replacement',
    'platform_context',
    'root_expiry_recovery_trust',
    'root_expiry_recovery_enrollment',
    'root_expiry_recovery_case',
    'root_expiry_recovery_challenge',
    'root_expiry_recovery_proof',
    'root_expiry_recovery_scope',
    'discovery_certificate_issuance',
    'discovery_certificate_issuer_attempt',
  ];
  const rows = tables
    .map(
      (table) =>
        `select '${table}' name, encode(sha256(convert_to(coalesce(jsonb_agg(to_jsonb(t) order by to_jsonb(t)::text),'[]'::jsonb)::text,'UTF8')),'hex') digest from control.${table} t`,
    )
    .join(' union all ');
  const preservation = JSON.parse(
    docker(
      'exec',
      pg.id,
      'psql',
      '-X',
      '-At',
      '-U',
      'openpc_control',
      '-d',
      'openpc_control',
      '-c',
      `select json_object_agg(name,digest) from (${rows}) preserved`,
    ),
  );
  return { ...auth, preservation };
};
async function checkedMaintenance(root, serial = true) {
  const manifest = await maintenanceDocument(root);
  assert.equal(manifest.maintenance?.kind, 'RETAINED_QA_SERIAL_V1');
  const containers = JSON.parse(docker('inspect', ...manifest.containers.map((c) => c.id)));
  const activeIds = docker('ps', '-q', '--filter', 'label=com.docker.compose.project')
    .split('\n')
    .filter(Boolean);
  const active = activeIds.length ? JSON.parse(docker('inspect', ...activeIds)) : [];
  const projects = active
    .map((c) => c.Config.Labels['com.docker.compose.project'])
    .filter((p) => p?.startsWith('openpc-local-e2e-'));
  validateQaMaintenanceContainers(manifest, containers, projects, true);
  assert.deepEqual(
    active
      .filter((c) => c.Config.Labels['com.docker.compose.project'] === manifest.project)
      .map((c) => c.Id)
      .sort(),
    containers
      .filter((c) => c.State.Running)
      .map((c) => c.Id)
      .sort(),
  );
  assert.deepEqual(
    authSnapshot(manifest),
    manifest.maintenance.auth,
    'Retained authentication or business state changed',
  );
  if (serial) {
    // Keepers belong to the canonical resource owner, not this linked
    // checkout's path-specific fixture module.
    const canonical = dirname(
      execFileSync('git', ['rev-parse', '--path-format=absolute', '--git-common-dir'], {
        encoding: 'utf8',
      }).trim(),
    );
    const keeperBytes =
      1024 *
      Number(
        execFileSync(
          'node',
          [
            join(canonical, 'tests/integration/local-runtime/rpc-journal-enospc-runtime.mjs'),
            'reservation',
          ],
          { encoding: 'utf8' },
        ),
      );
    const retained = containers
      .filter((c) => c.State.Running)
      .reduce((sum, c) => sum + c.HostConfig.Memory, 0);
    validateQaSerialBudget(
      Number(process.env.OPENPC_ADMITTED_HOST_MEMORY_KIB),
      Number(process.env.OPENPC_ADMITTED_EXTERNAL_MEMORY_KIB),
      retained,
      keeperBytes,
    );
    await maintenanceLocks(
      root,
      1.5,
      Math.ceil(((retained + keeperBytes + 6 * GiB) / GiB) * 1000) / 1000,
    );
  }
  return manifest;
}
export function qaComposeMounts(configuration, service) {
  const mounts = (service.volumes ?? []).map((v) => ({
    source: v.source,
    target: v.target,
    type: v.type,
    writable: !v.read_only,
  }));
  for (const [kind, prefix] of [
    ['secrets', '/run/secrets/'],
    ['configs', '/'],
  ]) {
    for (const binding of service[kind] ?? []) {
      const source = configuration[kind]?.[binding.source]?.file;
      assert.ok(typeof source === 'string' && source.startsWith('/'));
      const target = binding.target ?? binding.source;
      mounts.push({
        source,
        target: target.startsWith('/') ? target : prefix + target,
        type: 'bind',
        writable: false,
      });
    }
  }
  return mounts.sort((a, b) => a.target.localeCompare(b.target));
}
async function maintenanceCap(root) {
  await maintenanceCustody(root);
  const manifest = await checkedMaintenance(root, false);
  validateQaBuilder(JSON.parse(docker('inspect', serialBuilder))[0], 8 * GiB, false);
  const changes = {
    'control-pg': 0.25,
    'fact-pg': 0.25,
    'candidate-index-pg': 0.25,
    'identity-service': 0.5,
  };
  for (const [service, gib] of Object.entries(changes)) {
    const prior = manifest.maintenance.baseline.find((c) => c.service === service);
    const c = JSON.parse(docker('inspect', prior.id))[0];
    const cg = join('/sys/fs/cgroup', await cgroupOf(c.State.Pid));
    const current = Number(await readFile(join(cg, 'memory.current'), 'utf8'));
    assert.ok(current + 64 * 1024 ** 2 < gib * GiB, 'Insufficient live-footprint margin');
    prior.originalMemory ??= prior.memory;
    prior.originalSwap ??= prior.swap;
    docker('update', '--memory', String(gib * GiB), '--memory-swap', String(gib * GiB), c.Id);
    prior.memory = gib * GiB;
    prior.swap = gib * GiB;
    await saveMaintenance(root, manifest);
    const after = JSON.parse(docker('inspect', c.Id))[0];
    assert.equal(after.HostConfig.Memory, prior.memory);
    assert.equal(after.HostConfig.MemorySwap, prior.swap);
    assert.equal(after.State.StartedAt, prior.startedAt);
    assert.equal(after.State.OOMKilled, false);
    maintenanceLog(
      `OPENPC_QA_CAP|service=${service}|bytes=${prior.memory}|prior_current_bytes=${current}`,
    );
  }
  await checkedMaintenance(root, false);
}
async function maintenanceBegin(root, inspectOnly = false) {
  await maintenanceLocks(root, 1, 10.188, 1);
  const manifest = await maintenanceDocument(root);
  assert.ok(!manifest.maintenance, 'Unfinished maintenance must be reconciled');
  const containers = JSON.parse(docker('inspect', ...manifest.containers.map((c) => c.id)));
  const builder = JSON.parse(docker('inspect', serialBuilder))[0];
  validateQaBuilder(builder, 8 * GiB, false);
  const auth = authSnapshot(manifest);
  assert.equal(
    auth.policyRecords.filter((p) => p.policy_id === '01a0e8c8-9906-7227-89f3-584dd6a6ebb9').length,
    1,
    'Preserve the original tester policy draft',
  );
  manifest.maintenance = {
    kind: 'RETAINED_QA_SERIAL_V1',
    baseline: containers.map(containerView),
    auth,
    builderId: builder.Id,
    previousMaintenance: manifest.lastMaintenance,
    previousImageOverlay: await readFile(join(root, 'data/qa-maintenance-images.json'), 'utf8'),
  };
  const activeIds = docker('ps', '-q', '--filter', 'label=com.docker.compose.project')
    .split('\n')
    .filter(Boolean);
  const active = activeIds.length ? JSON.parse(docker('inspect', ...activeIds)) : [];
  validateQaMaintenanceContainers(
    manifest,
    containers,
    active
      .map((c) => c.Config.Labels['com.docker.compose.project'])
      .filter((p) => p?.startsWith('openpc-local-e2e-')),
    false,
  );
  assert.deepEqual(
    active
      .filter((c) => c.Config.Labels['com.docker.compose.project'] === manifest.project)
      .map((c) => c.Id)
      .sort(),
    containers.map((c) => c.Id).sort(),
  );
  const configuration = JSON.parse(
    execFileSync(
      manifest.command[0],
      [...manifest.command.slice(1), 'config', '--format', 'json'],
      { env: { ...process.env, ...manifest.environment }, encoding: 'utf8' },
    ),
  );
  for (const container of containers) {
    const service = configuration.services[container.Config.Labels['com.docker.compose.service']];
    assert.deepEqual(
      mountView(container),
      qaComposeMounts(configuration, service),
      'Compose mount drift',
    );
    for (const port of service.ports ?? []) assert.equal(port.host_ip, '127.0.0.1');
  }
  assert.ok(containers.every((c) => c.State.Health?.Status === 'healthy'));
  if (inspectOnly) {
    maintenanceLog(
      `OPENPC_QA_MAINTENANCE|INSPECTED|mutation=none|containers=${manifest.containers.length}`,
    );
    return;
  }
  await saveMaintenance(root, manifest);
  docker(
    'stop',
    '--time',
    '30',
    ...containers
      .filter((c) => !protectedServices.includes(c.Config.Labels['com.docker.compose.service']))
      .map((c) => c.Id),
  );
  await checkedMaintenance(root, false);
  maintenanceLog(
    `OPENPC_QA_MAINTENANCE|PAUSED|consumers=${manifest.containers.length - protectedServices.length}|protected=7`,
  );
}
async function builderConfiguration(container) {
  const archive = execFileSync('docker', ['cp', `${container}:/etc/buildkit/buildkitd.toml`, '-']);
  return execFileSync('tar', ['-xOf', '-'], { input: archive, encoding: 'utf8' });
}
const configurationValue = (text) =>
  JSON.parse(
    execFileSync(
      'python3',
      [
        '-c',
        'import sys,tomllib,json; print(json.dumps(tomllib.loads(sys.stdin.read()),sort_keys=True))',
      ],
      { input: text, encoding: 'utf8' },
    ),
  );
async function writeBuilderConfiguration(root, value) {
  const path = join(root, 'data/qa-buildkitd.toml');
  await writeFile(path, value, { mode: 0o600 });
  docker('cp', path, `${serialBuilder}:/etc/buildkit/buildkitd.toml`);
  await rm(path);
}
async function maintenanceBuilder(root, action) {
  if (action === 'restore') return maintenanceStop(root);
  const manifest = await checkedMaintenance(root, action !== 'restore');
  const repo = resolve(dirname(new URL(import.meta.url).pathname), '../../..');
  const configured = await readFile(join(repo, 'deploy/compose/local/buildkitd.toml'), 'utf8');
  const original =
    manifest.maintenance.builderConfigurationOriginal ??
    (await builderConfiguration(serialBuilder));
  assert.deepEqual(configurationValue(original), configurationValue(configured));
  assert.equal((original.match(/max-parallelism = 2/g) ?? []).length, 1);
  const serial = original.replace('max-parallelism = 2', 'max-parallelism = 1');
  const builder = JSON.parse(docker('inspect', serialBuilder))[0];
  assert.equal(builder.Id, manifest.maintenance.builderId);
  if (action === 'prepare') {
    validateQaBuilder(builder, 8 * GiB, false);
    assert.deepEqual(
      configurationValue(await builderConfiguration(serialBuilder)),
      configurationValue(original),
    );
    manifest.maintenance.builderConfigurationOriginal = original;
    await saveMaintenance(root, manifest);
    // Apply the hard cap while stopped, before any bootstrap can allocate.
    docker('update', '--memory', '4g', '--memory-swap', '4g', serialBuilder);
    await writeBuilderConfiguration(root, serial);
    validateQaBuilder(JSON.parse(docker('inspect', serialBuilder))[0], 4 * GiB, false);
  } else if (action === 'verify') {
    validateQaBuilder(builder, 4 * GiB, true);
    assert.deepEqual(
      configurationValue(await builderConfiguration(serialBuilder)),
      configurationValue(serial),
    );
  } else throw Error('Unknown builder maintenance operation');
  maintenanceLog(`OPENPC_QA_BUILDER|${action}|verified`);
}
export async function stopQaSerialBuilder(builder, expectedId, stop, restore) {
  assert.equal(builder.Id, expectedId);
  assert.ok([4 * GiB, 8 * GiB].includes(builder.HostConfig.Memory));
  validateQaBuilder(builder, builder.HostConfig.Memory, builder.State.Running);
  if (builder.State.Running) await stop();
  await restore();
}
async function maintenanceStop(root) {
  // Cleanup authenticates stable custody only. Admission, sessions, mutable
  // business state or memory pressure cannot prevent stopping our exact builder.
  await maintenanceCustody(root);
  const manifest = await maintenanceDocument(root);
  assert.equal(manifest.maintenance?.kind, 'RETAINED_QA_SERIAL_V1');
  const builder = JSON.parse(docker('inspect', serialBuilder))[0];
  const repo = resolve(dirname(new URL(import.meta.url).pathname), '../../..');
  const configured = await readFile(join(repo, 'deploy/compose/local/buildkitd.toml'), 'utf8');
  const original =
    manifest.maintenance.builderConfigurationOriginal ??
    (await builderConfiguration(serialBuilder));
  assert.deepEqual(configurationValue(original), configurationValue(configured));
  const serial = original.replace('max-parallelism = 2', 'max-parallelism = 1');
  await stopQaSerialBuilder(
    builder,
    manifest.maintenance.builderId,
    () => docker('buildx', 'stop', 'openpc-r1-local-v1'),
    async () => {
      const stopped = JSON.parse(docker('inspect', serialBuilder))[0];
      assert.equal(stopped.State.Running, false);
      const current = JSON.stringify(configurationValue(await builderConfiguration(serialBuilder)));
      assert.ok(
        [original, serial].some((value) => JSON.stringify(configurationValue(value)) === current),
      );
      await writeBuilderConfiguration(root, original);
      docker('update', '--memory', '8g', '--memory-swap', '8g', serialBuilder);
      validateQaBuilder(JSON.parse(docker('inspect', serialBuilder))[0], 8 * GiB, false);
      assert.equal(await builderConfiguration(serialBuilder), original);
    },
  );
  maintenanceLog('OPENPC_QA_BUILDER|STOPPED_RESTORED|memory_gib=8|parallelism=2');
}

const cgroupOf = async (pid) =>
  /^0::(.+)$/m.exec(await readFile(`/proc/${pid}/cgroup`, 'utf8'))?.[1];
async function maintenanceRun(root, argv, probe = false) {
  const manifest = await checkedMaintenance(root);
  await maintenanceBuilder(root, 'verify');
  const builder = JSON.parse(docker('inspect', serialBuilder))[0];
  const processPath = await cgroupOf(builder.State.Pid);
  const scope = `docker-${builder.Id}.scope`;
  assert.ok(processPath.split('/').includes(scope), 'Unknown builder cgroup owner');
  const builderPath = processPath.slice(0, processPath.indexOf(scope) + scope.length);
  assert.ok(builderPath?.startsWith('/') && builderPath !== '/' && !builderPath.includes('..'));
  const cg = join('/sys/fs/cgroup', builderPath);
  validateQaExecutor(
    builderPath,
    builderPath,
    (await readFile(join(cg, 'memory.max'), 'utf8')).trim(),
    (await readFile(join(cg, 'memory.swap.max'), 'utf8')).trim(),
  );
  const oom = async () =>
    Number(/^oom_kill\s+(\d+)/m.exec(await readFile(join(cg, 'memory.events'), 'utf8'))?.[1]);
  const initialOom = await oom();
  let command;
  if (probe) {
    command = [
      'docker',
      'buildx',
      'build',
      '--builder',
      'openpc-r1-local-v1',
      '--no-cache',
      '--progress=plain',
      '--output=type=cacheonly',
      '-',
    ];
  } else {
    command = JSON.parse(argv);
    const buildCommand = qaBuildCommand(manifest);
    const suffix = command.slice(buildCommand.length);
    assert.deepEqual(command.slice(0, buildCommand.length), buildCommand);
    assert.deepEqual(suffix.slice(0, -1), [
      'build',
      '--builder',
      'openpc-r1-local-v1',
      '--pull',
      '--build-arg',
      'OPENPC_BUILD_PROFILE=retained-qa-serial',
    ]);
    assert.ok(
      [
        'policy-service',
        'identity-service',
        'participant-service',
        'control-api',
        'admin-web',
        'control-worker',
        'fact-service',
      ].includes(suffix.at(-1)),
    );
    assert.equal(
      manifest.maintenance.executorVerified,
      true,
      'Verify a real executor before product compilation',
    );
  }
  const child = spawn(command[0], command.slice(1), {
    stdio: [probe ? 'pipe' : 'ignore', 'inherit', 'inherit'],
    env: { ...process.env, ...manifest.environment },
  });
  let completed = false,
    exitCode,
    failure,
    verified = false;
  child.once('error', (error) => {
    failure = error;
    completed = true;
  });
  child.once('exit', (code) => {
    exitCode = code;
    completed = true;
  });
  if (probe)
    child.stdin.end(
      `FROM docker.io/library/node:24.19.0-alpine@sha256:2a49bdf71e9fd965a58c1703fd9ddd205b34e5782b692a72dd1d248abb0beb43\nRUN ["node","-e","process.title='openpc-qa-probe';setTimeout(()=>process.exit(0),5000)"]\n`,
    );
  try {
    while (!completed) {
      assert.equal(await oom(), initialOom, 'Builder OOM stopped this build');
      if (probe && !verified) {
        const matches = [];
        for (const pid of await readdir('/proc')) {
          if (!/^\d+$/.test(pid)) continue;
          try {
            if ((await readFile(`/proc/${pid}/comm`, 'utf8')).trim() === 'openpc-qa-probe')
              matches.push(Number(pid));
          } catch (error) {
            if (!['ENOENT', 'ESRCH', 'EACCES'].includes(error.code)) throw error;
          }
        }
        assert.ok(matches.length <= 1, 'Ambiguous executor proof');
        if (matches.length === 1) {
          validateQaExecutor(
            builderPath,
            await cgroupOf(matches[0]),
            (await readFile(join(cg, 'memory.max'), 'utf8')).trim(),
            (await readFile(join(cg, 'memory.swap.max'), 'utf8')).trim(),
          );
          verified = true;
          maintenanceLog('OPENPC_QA_EXECUTOR|PASS|parent_limit_bytes=4294967296|swap_bytes=0');
        }
      }
      await new Promise((resolve) => setTimeout(resolve, probe ? 200 : 1000));
    }
    if (failure) throw failure;
    assert.equal(exitCode, 0, 'Original build command failed');
    assert.equal(await oom(), initialOom, 'Builder OOM invalidates the phase');
    if (probe) {
      assert.equal(verified, true, 'Executor proof did not run');
      manifest.maintenance.executorVerified = true;
      await saveMaintenance(root, manifest);
    }
    maintenanceLog(
      `OPENPC_QA_BUILD_MEMORY|peak_bytes=${(await readFile(join(cg, 'memory.peak'), 'utf8')).trim()}|cap_bytes=4294967296`,
    );
  } catch (error) {
    const current = JSON.parse(docker('inspect', serialBuilder))[0];
    assert.equal(current.Id, manifest.maintenance.builderId);
    validateQaBuilder(current, 4 * GiB, current.State.Running);
    if (current.State.Running) docker('buildx', 'stop', 'openpc-r1-local-v1');
    if (!completed) child.kill('SIGTERM');
    throw error;
  }
}
export function qaBuildCommand(manifest) {
  const command = [...manifest.command];
  const overlay = command.indexOf(join(manifest.root, 'data/qa-maintenance-images.json'));
  if (overlay !== -1) {
    assert.equal(command[overlay - 1], '-f');
    command.splice(overlay - 1, 2);
  }
  return command;
}
async function maintenanceBuild(root, predecessor) {
  const manifest = await checkedMaintenance(root);
  assert.match(predecessor, /^[a-f0-9]{40}$/);
  const repo = resolve(dirname(new URL(import.meta.url).pathname), '../../..');
  const script = `set -euo pipefail
repository_root=$1
run_root=$2
refresh_from=$3
canonical_external_root=$(dirname "$run_root")
owner_sentinel=$run_root/.openpc-local-runtime-owner
owner_record=$(cat "$owner_sentinel")
project=$4
data_root=$run_root/data
secret_root=$run_root/secrets
evidence_root=$run_root/evidence
source "$repository_root/scripts/maintenance/local-runtime-images.sh"
source "$repository_root/tests/integration/local-runtime/runner-harness.sh"
shift 4
compose=("$@")
trap 'first=$?; trap - EXIT; openpc_stop_owned_builder || { cleanup_status=$?; printf "OPENPC_QA_BUILD_CLEANUP|FAIL|status=%s\\n" "$cleanup_status" >&2; if [[ $first == 0 ]]; then first=$cleanup_status; fi; }; exit "$first"' EXIT
openpc_runtime_input_admission
openpc_storage_preflight
openpc_select_refresh_images
printf 'OPENPC_QA_SELECTED|%s\\n' "\${refresh_services[*]}"
openpc_prepare_builder retained-qa-serial "$run_root"
openpc_build_selected_images "\${refresh_services[@]}"
openpc_capture_built_images
openpc_stop_owned_builder
image_pairs=()
for service in "\${openpc_build_services[@]}"; do image_pairs+=("$service" "\${openpc_built_images[$service]}"); done
node "$repository_root/tests/integration/local-runtime/qa-sandbox.mjs" maintenance-images "$run_root" "$(node -e 'let o={};for(let i=1;i<process.argv.length;i+=2)o[process.argv[i]]=process.argv[i+1];process.stdout.write(JSON.stringify(o))' "\${image_pairs[@]}")"
`;
  const child = spawn(
    'bash',
    ['-c', script, '--', repo, root, predecessor, manifest.project, ...qaBuildCommand(manifest)],
    { stdio: 'inherit', env: { ...process.env, ...manifest.environment } },
  );
  const status = await new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('exit', resolve);
  });
  assert.equal(status, 0, 'Serial image phase failed; originals remain retained');
}
async function maintenanceImages(root, json) {
  const manifest = await checkedMaintenance(root);
  validateQaBuilder(JSON.parse(docker('inspect', serialBuilder))[0], 8 * GiB, false);
  const images = JSON.parse(json);
  assert.deepEqual(
    Object.keys(images).sort(),
    [
      'control-worker',
      'fact-service',
      'policy-service',
      'identity-service',
      'participant-service',
      'control-api',
      'admin-web',
    ].sort(),
  );
  for (const [service, id] of Object.entries(images)) {
    const image = JSON.parse(docker('image', 'inspect', id))[0];
    assert.equal(image.Id, id);
    assert.equal(image.Config.Labels['io.openpc.image.owner'], 'openpc-r1-local-runtime-v1');
    assert.equal(image.Config.Labels['io.openpc.image.service'], service);
  }
  manifest.maintenance.images = images;
  manifest.maintenance.source = execFileSync('git', ['rev-parse', 'HEAD'], {
    encoding: 'utf8',
  }).trim();
  await saveMaintenance(root, manifest);
  maintenanceLog('OPENPC_QA_IMAGES|BUILT|deployment=pending');
}
async function sameQaRuntimeArtifact(root, container, candidate) {
  if (container.image === candidate) return true;
  const [oldImage, newImage] = JSON.parse(docker('image', 'inspect', container.image, candidate));
  // Identity's final image copies only this bundle after its unchanged base,
  // user and package-tool removal layers. All other runtime inputs must match.
  if (
    JSON.stringify(oldImage.Config) !== JSON.stringify(newImage.Config) ||
    oldImage.Os !== newImage.Os ||
    oldImage.Architecture !== newImage.Architecture ||
    oldImage.RootFS.Layers.length !== newImage.RootFS.Layers.length ||
    JSON.stringify(oldImage.RootFS.Layers.slice(0, -1)) !==
      JSON.stringify(newImage.RootFS.Layers.slice(0, -1))
  )
    return false;
  const temporary = docker(
    'create',
    '--network',
    'none',
    '--label',
    `io.openpc.test-owner=${root}`,
    '--entrypoint',
    '/bin/true',
    candidate,
  );
  const artifact = (id) => {
    const tar = execFileSync('docker', ['cp', `${id}:/app/server.mjs`, '-'], {
      maxBuffer: 64 * 1024 ** 2,
    });
    return execFileSync(
      'python3',
      [
        '-c',
        `import sys,tarfile,hashlib,json
with tarfile.open(fileobj=sys.stdin.buffer,mode='r|') as t:
 rows=[]
 for m in t:
  if not m.isfile(): raise ValueError('Expected one executable bundle')
  h=hashlib.sha256(t.extractfile(m).read())
  rows.append([m.name,m.mode,m.uid,m.gid,m.size,h.hexdigest()])
 if len(rows)!=1: raise ValueError('Unexpected artifact cardinality')
 print(json.dumps(rows))`,
      ],
      { input: tar, encoding: 'utf8' },
    );
  };
  try {
    return artifact(container.id) === artifact(temporary);
  } finally {
    const c = JSON.parse(docker('inspect', temporary))[0];
    assert.equal(c.Config.Labels['io.openpc.test-owner'], root);
    assert.equal(c.State.Running, false);
    docker('rm', temporary);
  }
}
async function maintenanceFinish(root, mode) {
  assert.ok(['deploy', 'deploy-provider-approval', 'rollback'].includes(mode));
  // Exact broker-approved QA consumer refresh. All other protected services
  // retain their original process; ordinary deploy still requires byte identity.
  const refreshIdentity = mode === 'deploy-provider-approval';
  await maintenanceLocks(root, 1, 10.188, 1);
  const manifest = await maintenanceDocument(root);
  assert.equal(manifest.maintenance?.kind, 'RETAINED_QA_SERIAL_V1');
  validateQaBuilder(JSON.parse(docker('inspect', serialBuilder))[0], 8 * GiB, false);
  assert.deepEqual(authSnapshot(manifest), manifest.maintenance.auth);
  const prior = manifest.maintenance.baseline;
  const services = qaMaintenanceServices(manifest);
  const images = Object.fromEntries(prior.map((c) => [c.service, c.image]));
  const replacements = [];
  const currentIds = docker(
    'ps',
    '-aq',
    '--filter',
    `label=com.docker.compose.project=${manifest.project}`,
  )
    .split('\n')
    .filter(Boolean);
  const before = JSON.parse(docker('inspect', ...currentIds)).filter((c) =>
    services.includes(c.Config.Labels['com.docker.compose.service']),
  );
  assert.equal(before.length, services.length);
  assert.equal(
    new Set(before.map((c) => c.Config.Labels['com.docker.compose.service'])).size,
    services.length,
  );
  for (const c of before) {
    validateQaWorker(c, manifest.containers.find((p) => p.service === 'control-worker')?.image);
    const service = c.Config.Labels['com.docker.compose.service'],
      original = prior.find((p) => p.service === service);
    assert.ok([original.image, manifest.maintenance.images?.[service]].includes(c.Image));
    assert.deepEqual(mountView(c), original.mounts);
    assert.equal(c.HostConfig.Memory, original.memory);
    assert.equal(c.HostConfig.MemorySwap, original.swap);
    if (protectedServices.includes(service)) {
      assert.equal(c.Id, original.id);
      assert.equal(c.State.StartedAt, original.startedAt);
      assert.equal(c.State.Running, true);
    } else if (mode === 'rollback' && c.Image !== original.image) replacements.push(service);
  }
  if (mode === 'deploy' || refreshIdentity) {
    await checkedMaintenance(root, false);
    assert.ok(manifest.maintenance.images && manifest.maintenance.executorVerified);
    const identity = prior.find((c) => c.service === 'identity-service');
    if (refreshIdentity) {
      assert.equal(manifest.project, 'openpc-local-e2e-25a1cdecbd8f');
      assert.ok(manifest.maintenance.images['identity-service']);
      assert.notEqual(identity.image, manifest.maintenance.images['identity-service']);
    } else {
      assert.ok(
        await sameQaRuntimeArtifact(
          root,
          identity,
          manifest.maintenance.images['identity-service'],
        ),
        'Identity runtime inputs changed; preserve its process and stop deployment',
      );
    }
    for (const service of [
      ...(refreshIdentity ? ['identity-service'] : []),
      'policy-service',
      'participant-service',
      'control-api',
      'admin-web',
      'fact-service',
      ...(services.includes('control-worker') ? ['control-worker'] : []),
    ]) {
      const original = prior.find((c) => c.service === service),
        candidate = manifest.maintenance.images[service];
      assert.ok(candidate);
      const equivalent =
        original.image === candidate ||
        (service === 'participant-service' &&
          (await sameQaRuntimeArtifact(root, original, candidate)));
      if (!equivalent) {
        images[service] = candidate;
        replacements.push(service);
      }
    }
  }
  const overlay = join(root, 'data/qa-maintenance-images.json');
  const priorOverlay = JSON.parse(await readFile(overlay, 'utf8'));
  const configuration = {
    services: Object.fromEntries(
      Object.entries(images).map(([name, image]) => {
        const limits = prior.find((c) => c.service === name);
        return [
          name,
          {
            ...priorOverlay.services?.[name],
            image,
            mem_limit: limits.memory,
            memswap_limit: limits.swap,
          },
        ];
      }),
    ),
  };
  await writeFile(overlay, JSON.stringify(configuration), { mode: 0o600 });
  const command = manifest.command.includes(overlay)
    ? manifest.command
    : [...manifest.command, '-f', overlay];
  const compose = (...args) =>
    execFileSync(command[0], [...command.slice(1), ...args], {
      env: { ...process.env, ...manifest.environment },
      stdio: 'inherit',
      timeout: 180000,
    });
  try {
    for (const service of replacements)
      compose('up', '-d', '--wait', '--no-deps', '--no-build', '--pull', 'never', service);
    for (const service of [
      'policy-service',
      'participant-service',
      'fact-service',
      'control-api',
      'admin-web',
      'envoy',
      ...(services.includes('control-worker') ? ['control-worker'] : []),
    ]) {
      const unchanged = before.find(
        (c) => c.Config.Labels['com.docker.compose.service'] === service,
      );
      if (!replacements.includes(service)) docker('start', unchanged.Id);
    }
    let current;
    for (let attempt = 0; attempt < 40; attempt++) {
      const ids = docker(
        'ps',
        '-aq',
        '--filter',
        `label=com.docker.compose.project=${manifest.project}`,
      )
        .split('\n')
        .filter(Boolean);
      current = JSON.parse(docker('inspect', ...ids)).filter((c) =>
        services.includes(c.Config.Labels['com.docker.compose.service']),
      );
      if (
        current.length === services.length &&
        current.every((c) => c.State.Running && c.State.Health?.Status === 'healthy')
      )
        break;
      await new Promise((resolve) => setTimeout(resolve, 1500));
    }
    assert.equal(current.length, services.length);
    assert.ok(current.every((c) => c.State.Running && c.State.Health?.Status === 'healthy'));
    for (const c of current) {
      validateQaWorker(c, images['control-worker']);
      const service = c.Config.Labels['com.docker.compose.service'],
        old = prior.find((p) => p.service === service);
      assert.equal(c.Image, images[service]);
      assert.deepEqual(mountView(c), old.mounts);
      assert.equal(c.HostConfig.Memory, old.memory);
      assert.equal(c.HostConfig.MemorySwap, old.swap);
      if (
        protectedServices.includes(service) &&
        !(refreshIdentity && service === 'identity-service')
      ) {
        assert.equal(c.Id, old.id);
        assert.equal(c.State.StartedAt, old.startedAt);
      }
    }
    assert.deepEqual(authSnapshot(manifest), manifest.maintenance.auth);
    const previous = manifest.containers;
    manifest.containers = current.map((c) => ({
      id: c.Id,
      image: c.Image,
      service: c.Config.Labels['com.docker.compose.service'],
    }));
    manifest.command = command;
    manifest.lastMaintenance = {
      predecessor: manifest.maintenance.previousMaintenance,
      previousImageOverlay: manifest.maintenance.previousImageOverlay,
      source: manifest.maintenance.source ?? null,
      result: mode,
      previousContainers: previous,
      changedServices: replacements,
      protectedProcessesPreserved: !refreshIdentity,
      ...(refreshIdentity
        ? {
            identityProcessRefresh: {
              previous: prior.find((c) => c.service === 'identity-service'),
              current: current
                .filter((c) => c.Config.Labels['com.docker.compose.service'] === 'identity-service')
                .map(containerView)[0],
              reservation: 'QA-PROVIDER-APPROVAL-MODULE-UI-20260929',
              otherProtectedProcessesPreserved: true,
            },
          }
        : {}),
    };
    delete manifest.maintenance;
    await saveMaintenance(root, manifest);
    maintenanceLog(
      JSON.stringify({
        event: 'OPENPC_QA_RECONCILED',
        mode,
        healthy: services.length,
        changedServices: replacements,
        protectedOriginalProcesses: refreshIdentity ? 6 : 7,
        identityProcessRefreshed: refreshIdentity,
        originalAuthAndEffects: true,
        images: manifest.containers,
      }),
    );
  } catch (error) {
    // No replay or trust mutation. Preserve the original images and exact
    // failed phase for explicit rollback/reconciliation rather than guessing.
    process.stderr.write(
      'OPENPC_QA_RECONCILE|FAILED|original-images-retained|business-replay=forbidden\n',
    );
    throw error;
  }
}

// Retained profile activation changes configuration only. Existing OIDC signing
// keys/pending maps and all database processes retain their original incarnation.
async function maintenanceOidcBuild(root, command) {
  const repo = await maintenanceLocks(root, 3, 9, 40);
  const manifest = await maintenanceDocument(root);
  assert.ok(!manifest.maintenance && !manifest.durationProfilePending);
  validateQaComposeCommand(command, root, repo, manifest.project);
  for (let i = 2; i < command.length; i += 2)
    if (['-f', '--file'].includes(command[i])) {
      const info = await lstat(command[i + 1]);
      assert.ok(!info.isSymbolicLink() && info.uid === process.getuid());
      assert.equal(await realpath(command[i + 1]), command[i + 1]);
    }
  const ids = docker('ps', '-q', '--filter', 'label=com.docker.compose.project')
    .split('\n')
    .filter(Boolean);
  assert.ok(ids.length > 0);
  const actual = JSON.parse(docker('inspect', ...ids)).filter((c) =>
    c.Config.Labels['com.docker.compose.project'].startsWith('openpc-local-e2e-'),
  );
  const configuration = JSON.parse(
    execFileSync(command[0], [...command.slice(1), 'config', '--format', 'json'], {
      env: qaDurationEnvironment(process.env, manifest.environment, 'NORMAL'),
      encoding: 'utf8',
    }),
  );
  validateQaOidcBuild(actual, manifest.project, configuration);
  assert.equal(
    actual[0].Image,
    docker('image', 'inspect', actual[0].Config.Image, '--format', '{{.Id}}'),
  );
  validateQaBuilder(JSON.parse(docker('inspect', serialBuilder))[0], 8 * GiB, false);
  maintenanceLog(
    'OPENPC_QA_OIDC_BUILD|sole_retained_fixture=verified|external_budget_gib=9|business_consumers=stopped|mutation=none',
  );
}

const durationChangedServices = [
  'identity-service',
  'admin-web',
  'control-api',
  'policy-service',
  'envoy',
];
export const durationPrivateEnvironment = (environment, mode) => {
  assert.ok(['LOCAL_QA_10X', 'NORMAL'].includes(mode));
  const result = {
    ...environment,
    OPENPC_LOCAL_RUNTIME: '1',
    OPENPC_LOCAL_RUNTIME_QA_FIXTURE: '1',
  };
  delete result.OPENPC_LOCAL_QA_DURATION_PROFILE;
  if (mode === 'LOCAL_QA_10X') result.OPENPC_LOCAL_QA_DURATION_PROFILE = mode;
  return result;
};
const durationConfiguration = (command, environment) =>
  JSON.parse(
    execFileSync(command[0], [...command.slice(1), 'config', '--format', 'json'], {
      env: environment,
      encoding: 'utf8',
    }),
  );
const durationActual = (manifest) => {
  const ids = docker(
    'ps',
    '-aq',
    '--filter',
    `label=com.docker.compose.project=${manifest.project}`,
  )
    .split('\n')
    .filter(Boolean);
  assert.ok(ids.length > 0);
  return JSON.parse(docker('inspect', ...ids));
};
function durationExpected(configuration, name) {
  const image = JSON.parse(docker('image', 'inspect', configuration.services[name].image))[0];
  const networks = Object.fromEntries(
    Object.keys(configuration.services[name].networks ?? {}).map((key) => {
      const network = configuration.networks[key].name;
      return [network, JSON.parse(docker('network', 'inspect', network))[0].Id];
    }),
  );
  return durationExpectedState(
    configuration,
    name,
    image,
    networks,
    qaComposeMounts(configuration, configuration.services[name]),
  );
}
async function durationValidateCommand(command, root, repo, project) {
  validateQaComposeCommand(command, root, repo, project);
  for (let i = 2; i < command.length; i += 2)
    if (['-f', '--file'].includes(command[i])) {
      const info = await lstat(command[i + 1]);
      assert.ok(!info.isSymbolicLink() && info.uid === process.getuid());
      assert.equal(await realpath(command[i + 1]), command[i + 1]);
    }
}
async function durationReadback(root, manifest, repo) {
  const pending = manifest.durationProfilePending;
  assert.equal(pending.version, 1);
  assert.equal(pending.project, manifest.project);
  assert.deepEqual(pending.changed, durationChangedServices);
  for (const command of [pending.previousCommand, pending.targetCommand, pending.baselineCommand])
    await durationValidateCommand(command, root, repo, manifest.project);
  const priorEnv = qaDurationEnvironment(
    process.env,
    pending.previousEnvironment,
    pending.previousMode,
  );
  const env = qaDurationEnvironment(process.env, pending.environment, pending.mode);
  const previous = durationConfiguration(pending.previousCommand, priorEnv);
  const target = durationConfiguration(pending.targetCommand, env);
  const normal = durationConfiguration(
    pending.baselineCommand,
    qaDurationEnvironment(process.env, pending.baselineEnvironment, 'NORMAL'),
  );
  assert.equal(
    durationDigest(previous),
    pending.previousConfiguration,
    'Original configuration bytes drift',
  );
  assert.equal(
    durationDigest(target),
    pending.targetConfiguration,
    'Original target configuration bytes drift',
  );
  validateQaDurationConfiguration(normal, target, repo, pending.mode);
  for (const name of pending.changed)
    assert.equal(
      durationDigest(durationExpected(target, name)),
      pending.target[name],
      'Pinned image or target configuration drift',
    );
  const actual = durationActual(manifest);
  assert.deepEqual(
    authSnapshot({ ...manifest, containers: actual.map(containerView) }),
    pending.auth,
    'Original signed custody or effects changed',
  );
  const plan = durationTransitionPlan(pending, actual);
  return { actual, plan, target, environment: env };
}
async function durationFinalSave(root, manifest, pending, actual) {
  const updated = actual.filter((c) =>
    pending.previous.some((p) => p.service === c.Config.Labels['com.docker.compose.service']),
  );
  manifest.command = pending.targetCommand;
  manifest.environment = pending.environment;
  manifest.durationProfile = {
    mode: pending.mode,
    baselineCommand: pending.baselineCommand,
    baselineEnvironment: pending.baselineEnvironment,
    overlayPath: pending.overlayPath,
    previous: pending.previous,
    current: updated.map(containerView),
    protectedStates: pending.previous.filter((c) => !pending.changed.includes(c.service)),
    configurationVerified: true,
    originalEffectsPreserved: true,
  };
  manifest.containers = qaDurationRetainedContainers(
    manifest.containers,
    actual.map(containerView),
    updated.map(containerView),
  );
  qaMaintenanceServices(manifest);
  delete manifest.durationProfilePending;
  const temporary = join(root, 'data/qa-sandbox.json.maintenance-tmp');
  try {
    const info = await lstat(temporary);
    assert.ok(!info.isSymbolicLink() && info.uid === process.getuid() && (info.mode & 0o077) === 0);
    const first = JSON.parse(await readFile(temporary, 'utf8'));
    assert.equal(first.record, manifest.record);
    assert.equal(first.project, manifest.project);
    assert.deepEqual(first.command, pending.targetCommand);
    assert.equal(
      first.durationProfile?.mode,
      pending.mode,
      'Unrelated failed save requires separate reconciliation',
    );
    await rename(temporary, temporary + '.original-' + randomUUID());
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  await saveMaintenance(root, manifest);
}
async function durationComplete(root, manifest, repo) {
  const pending = manifest.durationProfilePending;
  await completeDurationTransition(pending, {
    read: async () => (await durationReadback(root, manifest, repo)).actual,
    authenticate: async () => {},
    recreate: async (name) => {
      const env = qaDurationEnvironment(process.env, pending.environment, pending.mode);
      execFileSync(
        pending.targetCommand[0],
        [
          ...pending.targetCommand.slice(1),
          'up',
          '-d',
          '--wait',
          '--no-deps',
          '--no-build',
          '--pull',
          'never',
          '--force-recreate',
          name,
        ],
        { env, stdio: 'inherit' },
      );
    },
    finish: async (actual) => durationFinalSave(root, manifest, pending, actual),
  });
  maintenanceLog(
    `OPENPC_QA_DURATION|mode=${pending.mode}|changed=5|original_signed_custody=preserved|oidc_process=preserved|original_transition=reconciled`,
  );
}
async function maintenanceDurationReadback(root) {
  const repo = await maintenanceLocks(root, 2, 9, 1);
  const manifest = await maintenanceDocument(root);
  assert.ok(manifest.durationProfilePending, 'No original pending transition');
  const { plan } = await durationReadback(root, manifest, repo);
  maintenanceLog(
    `OPENPC_QA_DURATION_READBACK|complete=${plan.complete}|remaining=${plan.remaining.join(',')}|mutation=none|original_signed_custody=preserved`,
  );
}
async function maintenanceDurationProfile(root, input) {
  const { mode, command } = input;
  assert.deepEqual(Object.keys(input).sort(), ['command', 'mode']);
  assert.ok(['LOCAL_QA_10X', 'NORMAL'].includes(mode));
  const repo = await maintenanceLocks(root, 2, 9, 1);
  let manifest = await maintenanceDocument(root);
  assert.ok(!manifest.maintenance);
  if (!manifest.durationProfilePending) {
    assert.deepEqual(command, manifest.command, 'Original retained command binding changed');
    const temporary = join(root, 'data/qa-sandbox.json.maintenance-tmp');
    let info;
    try {
      info = await lstat(temporary);
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    if (info) {
      assert.ok(
        !info.isSymbolicLink() && info.uid === process.getuid() && (info.mode & 0o077) === 0,
      );
      assert.equal(await realpath(temporary), temporary);
      const candidate = JSON.parse(await readFile(temporary, 'utf8'));
      manifest = await reconcileInitialDurationSave(manifest, candidate, input, {
        authenticate: (value) => durationReadback(root, value, repo),
        preserve: () =>
          copyFile(temporary, temporary + '.original-' + randomUUID(), fsConstants.COPYFILE_EXCL),
        publish: async (value) => {
          assert.deepEqual(JSON.parse(await readFile(temporary, 'utf8')), value);
          await rename(temporary, join(root, 'data/qa-sandbox.json'));
        },
      });
    }
  }
  if (manifest.durationProfilePending) {
    assert.equal(
      mode,
      manifest.durationProfilePending.mode,
      'A new transition cannot replace the original',
    );
    assert.deepEqual(
      command,
      manifest.durationProfilePending.previousCommand,
      'A new command cannot replace the original',
    );
    await durationReadback(root, manifest, repo);
    return durationComplete(root, manifest, repo);
  }
  await durationValidateCommand(command, root, repo, manifest.project);
  validateQaBuilder(JSON.parse(docker('inspect', serialBuilder))[0], 8 * GiB, false);
  const actual = durationActual(manifest),
    running = actual.filter((c) => c.State.Running);
  const names = running.map((c) => c.Config.Labels['com.docker.compose.service']);
  assert.equal(new Set(names).size, names.length);
  assert.ok(
    [...durationChangedServices, 'oidc-emulator', 'control-pg'].every((name) =>
      names.includes(name),
    ),
  );
  const previousMode = manifest.durationProfile?.mode ?? 'NORMAL';
  const previousEnvironment = durationPrivateEnvironment(manifest.environment, previousMode);
  const baselineEnvironment =
    manifest.durationProfile?.baselineEnvironment ??
    durationPrivateEnvironment(manifest.environment, 'NORMAL');
  const baselineCommand = manifest.durationProfile?.baselineCommand ?? command;
  const normal = durationConfiguration(
    baselineCommand,
    qaDurationEnvironment(process.env, baselineEnvironment, 'NORMAL'),
  );
  validateQaDurationConfiguration(normal, normal, repo, 'NORMAL');
  const previous = durationConfiguration(
    command,
    qaDurationEnvironment(process.env, previousEnvironment, previousMode),
  );
  for (const c of running) {
    assert.equal(c.State.OOMKilled, false);
    assert.equal(c.State.Health?.Status, 'healthy');
    const name = c.Config.Labels['com.docker.compose.service'];
    const originalState = durationContainerState(c),
      expectedState = durationExpected(previous, name);
    const drift = Object.keys(expectedState).filter(
      (key) => durationDigest(originalState[key]) !== durationDigest(expectedState[key]),
    );
    assert.equal(
      durationDigest(originalState),
      durationDigest(expectedState),
      `Original ${name} configuration drift in: ${drift.join(',')}`,
    );
  }
  const environment = durationPrivateEnvironment(baselineEnvironment, mode);
  let targetCommand = baselineCommand,
    overlayPath;
  if (mode === 'LOCAL_QA_10X') {
    const overlay = qaDurationComposeOverlay(
      repo,
      qaDurationEnvironment(process.env, environment, mode),
    );
    const gateway = overlay.services.envoy.volumes[0].source;
    const info = await lstat(gateway);
    assert.ok(!info.isSymbolicLink());
    assert.equal(await realpath(gateway), gateway);
    overlayPath = join(root, `data/qa-duration-${randomUUID()}.json`);
    await writeFile(overlayPath, JSON.stringify(overlay), { flag: 'wx', mode: 0o400 });
    targetCommand = [...baselineCommand, '-f', overlayPath];
  }
  const target = durationConfiguration(
    targetCommand,
    qaDurationEnvironment(process.env, environment, mode),
  );
  validateQaDurationConfiguration(normal, target, repo, mode);
  const pending = {
    version: 1,
    project: manifest.project,
    mode,
    previousMode,
    previousCommand: command,
    previousEnvironment,
    targetCommand,
    environment,
    baselineCommand,
    baselineEnvironment,
    overlayPath,
    changed: durationChangedServices,
    previousConfiguration: durationDigest(previous),
    targetConfiguration: durationDigest(target),
    previous: running.map((c) => ({
      ...containerView(c),
      configuration: durationDigest(durationContainerState(c)),
    })),
    target: Object.fromEntries(
      durationChangedServices.map((name) => [name, durationDigest(durationExpected(target, name))]),
    ),
    auth: authSnapshot({ ...manifest, containers: actual.map(containerView) }),
  };
  manifest.durationProfilePending = pending;
  await saveMaintenance(root, manifest);
  await durationComplete(root, manifest, repo);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [action, root, argv] = process.argv.slice(2);
  if (action === 'prepare') await prepare(root);
  else if (action === 'provider-renewal-trust') await providerRenewalTrust(root, JSON.parse(argv));
  else if (action === 'seed') await seed(root);
  else if (action === 'retain') {
    await retain(root, argv);
  } else if (['start', 'stop', 'status'].includes(action)) await lifecycle(action, root);
  else if (action === 'maintenance-cap') await maintenanceCap(root);
  else if (action === 'maintenance-begin') await maintenanceBegin(root);
  else if (action === 'maintenance-inspect') await maintenanceBegin(root, true);
  else if (action === 'maintenance-check') await checkedMaintenance(root);
  else if (action === 'maintenance-builder') await maintenanceBuilder(root, argv);
  else if (action === 'maintenance-executor') await maintenanceRun(root, undefined, true);
  else if (action === 'maintenance-command') await maintenanceRun(root, argv);
  else if (action === 'maintenance-build') await maintenanceBuild(root, argv);
  else if (action === 'maintenance-images') await maintenanceImages(root, argv);
  else if (action === 'maintenance-stop') await maintenanceStop(root);
  else if (action === 'maintenance-duration-profile')
    await maintenanceDurationProfile(root, JSON.parse(argv));
  else if (action === 'maintenance-duration-readback') await maintenanceDurationReadback(root);
  else if (action === 'maintenance-oidc-build') await maintenanceOidcBuild(root, JSON.parse(argv));
  else if (action === 'maintenance-finish') await maintenanceFinish(root, argv);
  else throw new Error('Unknown QA sandbox action');
}
