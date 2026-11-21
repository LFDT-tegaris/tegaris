import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { setTimeout as pause } from 'node:timers/promises';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const execute = promisify(execFile);
const container = process.env.OPENPC_CONTROL_INSTALLATION_TEST_CONTAINER;
const businessTables = [
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

async function docker(...args) {
  return (
    await execute('docker', args, { timeout: 180_000, maxBuffer: 4 * 1024 * 1024 })
  ).stdout.trim();
}
async function sql(statement) {
  return docker(
    'exec',
    container,
    'psql',
    '-XqAt',
    '-v',
    'ON_ERROR_STOP=1',
    '-U',
    'postgres',
    '-d',
    'openpc_control',
    '-c',
    statement,
  );
}
async function migrate(mode) {
  return docker(
    'exec',
    '-e',
    'PGHOST=127.0.0.1',
    '-e',
    'PGUSER=postgres',
    '-e',
    'PGDATABASE=openpc_control',
    container,
    'sh',
    '/local/migrate.sh',
    mode,
  );
}
async function businessState() {
  // A closed table list makes missing owners fail instead of silently skipping
  // them. Include actual rows, so a populated repeat cannot rewrite grants.
  return JSON.parse(
    await sql(
      `select jsonb_object_agg(name,rows) from (${businessTables
        .map(
          (name) =>
            `select '${name}' name,coalesce(jsonb_agg(to_jsonb(t) order by to_jsonb(t)::text),'[]') rows from control.${name} t`,
        )
        .join(' union all ')}) state`,
    ),
  );
}
const journal = () =>
  sql(
    "select coalesce(jsonb_agg(to_jsonb(m) order by path),'[]'::jsonb) from openpc_local.migration m",
  );

test(
  'Control installation creates service roles and catalogue without business trust or effects',
  { skip: !container, timeout: 180_000 },
  async () => {
    assert.match(container, /^openpc-participant-readback-[0-9]+$/u);
    const empty = Object.fromEntries(businessTables.map((name) => [name, []]));
    assert.deepEqual(await businessState(), empty);
    const history = await journal();
    if ((await sql("select to_regclass('openpc_local.baseline_lineage') is not null")) === 't') {
      const baseline = JSON.parse(
        await readFile(
          new URL('../../../migrations/postgres/baseline-v1/baseline.json', import.meta.url),
          'utf8',
        ),
      );
      assert.deepEqual(JSON.parse(history) ?? [], []);
      assert.deepEqual(
        JSON.parse(
          await sql(
            "select jsonb_agg(to_jsonb(l)-'recorded_at') from openpc_local.baseline_lineage l",
          ),
        ),
        [
          {
            baseline_id: baseline.baseline_id,
            source_commit: baseline.source_commit,
            sql_sha256: baseline.files['control.sql'],
            catalog_sha256: baseline.catalog_profiles.canonical.catalog_sha256,
            catalog_profile: 'canonical',
            origin: 'FRESH',
          },
        ],
      );
    } else {
      assert.ok(JSON.parse(history).length > 0);
    }
    assert.equal(
      await sql(`select count(*) from control.action_intent where
        action_intent_id='ACT-PARTICIPANTS_CREATE_RESOURCE-V1'
        and maker_checker_required and step_up_required`),
      '1',
    );
    assert.equal(
      await sql(`select count(*) from pg_roles where rolname in
        ('openpc_identity_runtime','openpc_participant_runtime','openpc_configuration_runtime',
         'openpc_policy_runtime','openpc_local_control_worker','openpc_source_control_reader')
        and rolcanlogin and not rolsuper and not rolbypassrls and not rolcreaterole
        and not rolcreatedb and not rolreplication`),
      '6',
    );
    assert.equal(
      await docker(
        'exec',
        container,
        'sh',
        '-eu',
        '-c',
        'PGPASSWORD=$(cat /run/secrets/identity_runtime_db_password); export PGPASSWORD; exec psql -XqAt -v ON_ERROR_STOP=1 -h 127.0.0.1 -U openpc_identity_runtime -d openpc_control -c "select current_user"',
      ),
      'openpc_identity_runtime',
    );
    await migrate('control-installation');
    assert.deepEqual(await businessState(), empty);
    assert.equal(await journal(), history);
    await assert.rejects(migrate('control-installation-invalid'));
    assert.deepEqual(await businessState(), empty);
    await docker('restart', container);
    // Query failures are readiness failures; do not use a timer to infer success.
    for (let attempt = 0; ; attempt++) {
      try {
        await docker('exec', container, 'pg_isready', '-U', 'postgres', '-d', 'openpc_control');
        break;
      } catch (error) {
        if (attempt >= 59) throw error;
        await pause(100);
      }
    }
    assert.deepEqual(await businessState(), empty);
    assert.equal(await journal(), history);

    // Compatibility qualification only: the ordinary automated mode retains
    // its legacy fixtures. They are never treated as legitimate manual trust.
    await migrate('control');
    const automated = await businessState();
    assert.equal(automated.participant.length, 1);
    assert.equal(automated.principal.length, 2);
    assert.ok(automated.authority_envelope.length > 0);
    assert.ok(automated.assignment.length > 0);
    await migrate('control-installation');
    assert.deepEqual(await businessState(), automated);
    assert.equal(await journal(), history);
  },
);
