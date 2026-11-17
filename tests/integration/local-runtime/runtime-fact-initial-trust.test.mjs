import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { Pool } from 'pg';
import {
  decodeEnvelopeScope,
  encodeEnvelopeScope,
} from '../../../packages/security-kernel/src/index.ts';
import {
  factInitialScope,
  factTrustScenario,
  installRuntimeFactInitialTrust,
} from './runtime-fact-initial-trust.mjs';

const resource = 'urn:openpc:resource:018f0000-0000-7000-8000-000000008390';
const participant = '018f0000-0000-7000-8000-000000000101';
const privacy = '018f0000-0000-7000-8000-000000007201';

test('Fact initial trust is a finite, canonical administrative ceiling without runtime authority', () => {
  const start = Date.now();
  const scope = factInitialScope(start, resource);
  assert.deepEqual(decodeEnvelopeScope(encodeEnvelopeScope(scope)), scope);
  assert.deepEqual(scope.administration.resourceIds, [resource]);
  for (const value of ['*', '', 'urn:openpc:resource:invalid'])
    assert.throws(() => factInitialScope(start, value));
  assert.deepEqual(scope.administration.participantIds, [participant]);
  assert.deepEqual(scope.administration.privacyDomainIds, [privacy]);
  assert.deepEqual(scope.administration.actionIntentIds, ['ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1']);
  assert.deepEqual(scope.administration.riskClasses, ['STANDARD']);
  for (const values of Object.values(scope.runtime)) assert.deepEqual(values, []);
  assert.equal(scope.onwardDelegationDepth, 0);
  assert.equal(BigInt(scope.validUntilNs) - BigInt(scope.validFromNs), 86400000000000n);
  assert.deepEqual(
    factInitialScope(start, resource),
    scope,
    'Recovery never renews the declared lifetime',
  );
  for (const value of [0, -1, NaN, Infinity, Number.MAX_SAFE_INTEGER])
    assert.throws(() => factInitialScope(value, resource));
});

test('the positive and quarantine scenarios have distinct fixed trust identities', () => {
  const a = factTrustScenario(2),
    b = factTrustScenario(3);
  for (const key of Object.keys(a)) assert.notEqual(a[key], b[key]);
  for (const generation of [0, 1, 4, NaN, '2']) assert.throws(() => factTrustScenario(generation));
});

test('a retained legacy or foreign Fact envelope cannot be rebound or invoke an installer', async () => {
  for (const root of ['018f0000-0000-7000-8000-000000000135', null, 'foreign']) {
    const queries = [];
    const client = {
      query: async (sql) => {
        queries.push(sql);
        return { rows: [{ platform_context_id: root }] };
      },
    };
    await assert.rejects(
      installRuntimeFactInitialTrust(client, '/unavailable', participant, privacy, resource),
      /cannot be rebound/,
    );
    await assert.rejects(
      installRuntimeFactInitialTrust(client, '/unavailable', participant, privacy, resource, 3),
      /cannot be rebound/,
    );
    assert.equal(queries.length, 2);
    assert.match(queries[0], /^select /u);
  }
});

test('Fact initial trust rejects a different participant or privacy domain before database access', async () => {
  const client = { query: async () => assert.fail('No database access permitted') };
  await assert.rejects(
    installRuntimeFactInitialTrust(client, '/unavailable', 'foreign', privacy, resource),
  );
  await assert.rejects(
    installRuntimeFactInitialTrust(client, '/unavailable', participant, 'foreign', resource),
  );
});

test(
  'PG: initial Fact scope recovers partial commits without business effects or renewed authority',
  {
    skip: !process.env.OPENPC_I02_ADMIN_DATABASE_URL,
    timeout: 120000,
  },
  async () => {
    const root = join(process.env.OPENPC_TEST_TMP_ROOT, 'fact-initial-trust');
    await mkdir(root, { mode: 0o700 });
    const pool = new Pool({ connectionString: process.env.OPENPC_I02_ADMIN_DATABASE_URL, max: 1 });
    const client = await pool.connect();
    const initialRoot = '018f0000-0000-7000-8000-000000008384';
    const install = (connection = client, directory = root) =>
      installRuntimeFactInitialTrust(connection, directory, participant, privacy, resource);
    const businessState = async () =>
      (
        await client.query(`select
    (select count(*) from control.assignment) assignments,
    (select count(*) from control.mutation_candidate) candidates,
    (select count(*) from control.approval_request) approvals,
    (select count(*) from control.policy_activation) activations`)
      ).rows;
    const noInstallerLogin = async () =>
      assert.equal(
        (
          await client.query(
            "select count(*)::int count from pg_roles where rolname like 'openpc_fact_installer_%' and rolcanlogin",
          )
        ).rows[0].count,
        0,
      );
    try {
      await client.query(
        `insert into control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state)
      values($1,$2,'Fact initial trust recovery','PARTICIPANT_LOCAL','LOCAL','ACTIVE')`,
        [privacy, participant],
      );
      // Existing USER operators administer Facts; this is separate from the
      // workload grantability being initialized for the acquired candidate.
      await client.query(
        `insert into control.authority_envelope(
        authority_envelope_id,participant_id,principal_id,maker_principal_id,checker_principal_id,
        authority_epoch,delegation_epoch,state,valid_from,valid_until,semantic_cbor,semantic_digest,cose_sign1,
        privacy_domain_ids,action_intent_ids,resource_ids,risk_classes,maker_checker_required,step_up_required,onward_delegation_depth)
        select '018f0000-0000-7000-8000-000000008421',participant_id,principal_id,maker_principal_id,checker_principal_id,
        authority_epoch,delegation_epoch,state,valid_from,valid_until,semantic_cbor,sha256(convert_to('018f0000-0000-7000-8000-000000008421','UTF8')),cose_sign1,
        array[$1::text],array['ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1'],resource_ids,risk_classes,maker_checker_required,step_up_required,onward_delegation_depth
        from control.authority_envelope where authority_envelope_id='018f0000-0000-7000-8000-000000000121'`,
        [privacy],
      );
      await client.query(
        `insert into control.assignment(assignment_id,participant_id,principal_id,authority_envelope_id,delegation_epoch,scope_digest,
        valid_during,state,created_by_principal_id,privacy_domain_ids,action_intent_ids,resource_ids,risk_classes,maker_checker_required,step_up_required,onward_delegation_depth,role_id)
        select '018f0000-0000-7000-8000-000000008422',participant_id,principal_id,'018f0000-0000-7000-8000-000000008421',delegation_epoch,scope_digest,
        valid_during,state,created_by_principal_id,array[$1::text],array['ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1'],resource_ids,risk_classes,maker_checker_required,step_up_required,onward_delegation_depth,role_id
        from control.assignment where assignment_id='018f0000-0000-7000-8000-000000000122'`,
        [privacy],
      );
      const originalBusinessState = await businessState();
      // A database-side fault rejects the scope transaction after the independent
      // operations installation commits. No business state is manufactured.
      await client.query(`create function public.reject_fact_fixture_scope() returns trigger language plpgsql as $$
      begin if new.platform_context_id='${initialRoot}' then raise exception 'fixture scope installation interruption'; end if; return new; end $$;
      create trigger reject_fact_fixture_scope before insert on control.platform_context
      for each row execute function public.reject_fact_fixture_scope()`);
      await assert.rejects(install());
      await noInstallerLogin();
      assert.equal(
        (
          await client.query(
            "select count(*)::int count from control.operations_installation where environment_id='local-first-policy-fact'",
          )
        ).rows[0].count,
        1,
      );
      assert.equal(
        (
          await client.query(
            'select count(*)::int count from control.platform_context where platform_context_id=$1',
            [initialRoot],
          )
        ).rows[0].count,
        0,
      );
      const preparedBytes = await readFile(join(root, 'runtime-fact-initial-trust.json'));
      await client.query(
        'drop trigger reject_fact_fixture_scope on control.platform_context; drop function public.reject_fact_fixture_scope()',
      );
      // Lose the response after the real scope commit, before fixture readback.
      const lostResponse = {
        connectionParameters: client.connectionParameters,
        query: (sql, values) => {
          if (sql.startsWith('select s.scope_cbor')) throw new Error('fixture lost scope response');
          return client.query(sql, values);
        },
      };
      await assert.rejects(install(lostResponse), /fixture lost scope response/);
      await noInstallerLogin();
      assert.equal(
        (
          await client.query(
            'select count(*)::int count from control.platform_envelope_scope where platform_context_id=$1',
            [initialRoot],
          )
        ).rows[0].count,
        1,
      );
      const installed = await install();
      const repeated = await install();
      assert.deepEqual(repeated, installed);
      assert.equal(installed.resourceId, resource);
      assert.deepEqual(
        await readFile(join(root, 'runtime-fact-initial-trust.json')),
        preparedBytes,
      );
      await noInstallerLogin();
      const stored = (
        await client.query(
          'select scope_cbor from control.platform_envelope_scope where platform_context_id=$1',
          [initialRoot],
        )
      ).rows[0];
      assert.deepEqual(
        decodeEnvelopeScope(stored.scope_cbor),
        factInitialScope(Date.parse(installed.validFrom), resource),
      );
      for (const [name, change] of [
        ['expired', { startMs: Date.now() - 86400001 }],
        ['changed-time', { startMs: Date.parse(installed.validFrom) - 1000 }],
        ['changed-resource', { resourceId: resource.replace(/8390$/u, '8391') }],
      ]) {
        const directory = join(root, name);
        await mkdir(directory, { mode: 0o700 });
        await writeFile(
          join(directory, 'runtime-fact-initial-trust.json'),
          JSON.stringify({ ...JSON.parse(preparedBytes), ...change }),
          { mode: 0o400, flag: 'wx' },
        );
        await assert.rejects(install(client, directory));
        await noInstallerLogin();
        assert.deepEqual(await install(), installed);
      }
      const roleFailure = {
        connectionParameters: client.connectionParameters,
        query: (sql, values) => {
          if (sql.startsWith('grant openpc_control_owner'))
            throw new Error('fixture role grant interruption');
          return client.query(sql, values);
        },
      };
      await assert.rejects(install(roleFailure), /fixture role grant interruption/);
      await noInstallerLogin();
      // The quarantine scenario has separate initial authority; it cannot renew
      // or broaden the positive scenario, nor duplicate its resource permission.
      await assert.rejects(
        installRuntimeFactInitialTrust(client, root, participant, privacy, resource, 3),
        /cannot replace/,
      );
      const quarantineResource = resource.replace(/8390$/u, '8391');
      for (const grantedResource of [quarantineResource, '*']) {
        await client.query('begin');
        try {
          await client.query(
            "insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch) values('018f0000-0000-7000-8000-000000008423',$1,'WORKLOAD','Existing Fact workload','ACTIVE',1)",
            [participant],
          );
          await client.query(
            `insert into control.assignment(assignment_id,participant_id,principal_id,authority_envelope_id,delegation_epoch,scope_digest,
          valid_during,state,created_by_principal_id,privacy_domain_ids,action_intent_ids,resource_ids,risk_classes,maker_checker_required,step_up_required,onward_delegation_depth,role_id)
          select '018f0000-0000-7000-8000-000000008424',participant_id,'018f0000-0000-7000-8000-000000008423',authority_envelope_id,delegation_epoch,scope_digest,
          valid_during,state,created_by_principal_id,privacy_domain_ids,action_intent_ids,array[$1::text],risk_classes,maker_checker_required,step_up_required,onward_delegation_depth,role_id
          from control.assignment where assignment_id='018f0000-0000-7000-8000-000000008422'`,
            [grantedResource],
          );
          await assert.rejects(
            installRuntimeFactInitialTrust(
              client,
              root,
              participant,
              privacy,
              quarantineResource,
              3,
            ),
            /cannot replace a workload grant/,
          );
        } finally {
          await client.query('rollback');
        }
      }
      const quarantine = await installRuntimeFactInitialTrust(
        client,
        root,
        participant,
        privacy,
        quarantineResource,
        3,
      );
      assert.equal(quarantine.platformContextId, factTrustScenario(3).platformContextId);
      assert.equal(quarantine.resourceId, quarantineResource);
      assert.deepEqual(
        await installRuntimeFactInitialTrust(
          client,
          root,
          participant,
          privacy,
          quarantineResource,
          3,
        ),
        quarantine,
      );
      assert.deepEqual(await install(), installed);
      assert.deepEqual(
        await readFile(join(root, 'runtime-fact-initial-trust.json')),
        preparedBytes,
      );
      assert.deepEqual(
        (
          await client.query(
            'select scope_cbor from control.platform_envelope_scope where platform_context_id=$1',
            [initialRoot],
          )
        ).rows[0],
        stored,
      );
      await noInstallerLogin();
      assert.deepEqual(await businessState(), originalBusinessState);
      assert.equal(
        (
          await client.query(
            'select count(*)::int count from control.authority_envelope where authority_envelope_id=$1',
            ['018f0000-0000-7000-8000-000000008383'],
          )
        ).rows[0].count,
        0,
      );
    } finally {
      client.release();
      await pool.end();
    }
  },
);
