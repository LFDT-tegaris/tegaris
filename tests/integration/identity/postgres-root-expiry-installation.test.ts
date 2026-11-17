import { execFile } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { lstat, realpath, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { Pool } from 'pg';
import { expect, it } from 'vitest';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import {
  assertNativeRootExpiryDatabaseTarget,
  nativeRootExpiryInstallationInput,
  verifyNativeRootExpiryReceivingTrust,
} from './root-expiry-installation-native.js';

const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
const container = process.env.OPENPC_PLATFORM_SCOPE_CONTAINER;
const integration = adminUrl && runtimeUrl && container ? it : it.skip;
const execute = promisify(execFile);

it('authenticates Root-expiry installation sources before allocating PostgreSQL', async () => {
  expect(
    (await nativeRootExpiryInstallationInput('root-expiry-preflight')).sourceAuthentication.version,
  ).toBe(1);
});

function targetFixture() {
  return {
    container: 'openpc-participant-readback-1234',
    scratch: '/owned/native-recovery',
    adminUrl: 'postgresql://postgres:synthetic@127.0.0.1:25432/openpc_control',
    runtimeUrl: 'postgresql://openpc_identity_runtime:synthetic@127.0.0.1:25432/openpc_control',
    inspection: {
      Id: 'a'.repeat(64),
      Name: '/openpc-participant-readback-1234',
      State: { Running: true },
      Config: { Labels: { 'io.openpc.test-owner': '/owned/native-recovery' } },
      NetworkSettings: { Ports: { '5432/tcp': [{ HostIp: '127.0.0.1', HostPort: '25432' }] } },
    },
  };
}

it('binds Root-expiry installation to its owned database', () => {
  expect(assertNativeRootExpiryDatabaseTarget(targetFixture())).toEqual({
    id: 'a'.repeat(64),
    port: '25432',
  });
});

const wrongTargetCases: [string, (value: ReturnType<typeof targetFixture>) => void][] = [
  [
    'unowned name',
    (value) => {
      value.container = 'foreign-database';
    },
  ],
  [
    'different inspected name',
    (value) => {
      value.inspection.Name = '/openpc-participant-readback-5678';
    },
  ],
  [
    'foreign owner',
    (value) => {
      value.inspection.Config.Labels['io.openpc.test-owner'] = '/other/fixture';
    },
  ],
  [
    'relative scratch',
    (value) => {
      value.scratch = 'relative/fixture';
    },
  ],
  [
    'stopped database',
    (value) => {
      value.inspection.State.Running = false;
    },
  ],
  [
    'invalid container identity',
    (value) => {
      value.inspection.Id = 'short-id';
    },
  ],
  [
    'non-loopback publication',
    (value) => {
      value.inspection.NetworkSettings.Ports['5432/tcp'][0]!.HostIp = '0.0.0.0';
    },
  ],
  [
    'multiple publications',
    (value) => {
      value.inspection.NetworkSettings.Ports['5432/tcp'].push({
        HostIp: '127.0.0.1',
        HostPort: '25433',
      });
    },
  ],
  [
    'out-of-range port',
    (value) => {
      value.inspection.NetworkSettings.Ports['5432/tcp'][0]!.HostPort = '65536';
    },
  ],
  [
    'foreign admin host',
    (value) => {
      value.adminUrl = value.adminUrl.replace('127.0.0.1', '192.0.2.1');
    },
  ],
  [
    'foreign runtime host',
    (value) => {
      value.runtimeUrl = value.runtimeUrl.replace('127.0.0.1', '192.0.2.1');
    },
  ],
  [
    'different admin port',
    (value) => {
      value.adminUrl = value.adminUrl.replace(':25432', ':25433');
    },
  ],
  [
    'different runtime port',
    (value) => {
      value.runtimeUrl = value.runtimeUrl.replace(':25432', ':25433');
    },
  ],
  [
    'different database',
    (value) => {
      value.adminUrl = value.adminUrl.replace('/openpc_control', '/other');
    },
  ],
  [
    'different runtime role',
    (value) => {
      value.runtimeUrl = value.runtimeUrl.replace('openpc_identity_runtime', 'postgres');
    },
  ],
  [
    'endpoint override parameters',
    (value) => {
      value.adminUrl += '?host=192.0.2.1';
    },
  ],
];
it.each(wrongTargetCases)('rejects Root-expiry installation target: %s', (_name, alter) => {
  const input = targetFixture();
  alter(input);
  expect(() => assertNativeRootExpiryDatabaseTarget(input)).toThrow();
});

integration(
  'installs finite recovery trust after genuine Root expiry without granting authority and retains it after restart',
  async () => {
    expect(container).toMatch(/^openpc-participant-readback-[0-9]+$/u);
    const scratch = process.env.OPENPC_TEST_TMP_ROOT;
    if (!scratch?.startsWith('/')) throw new Error('Absolute isolated fixture scratch is required');
    expect((await lstat(scratch)).isSymbolicLink()).toBe(false);
    expect(await realpath(scratch)).toBe(scratch);
    const inspected = await execute(
      'docker',
      [
        'inspect',
        '--format',
        '{"Id":{{json .Id}},"Name":{{json .Name}},"State":{"Running":{{json .State.Running}}},"Config":{"Labels":{{json .Config.Labels}}},"NetworkSettings":{"Ports":{{json .NetworkSettings.Ports}}}}',
        container!,
      ],
      { timeout: 10000, maxBuffer: 16384 },
    );
    const target = assertNativeRootExpiryDatabaseTarget({
      container: container!,
      scratch,
      adminUrl: adminUrl!,
      runtimeUrl: runtimeUrl!,
      inspection: JSON.parse(inspected.stdout),
    });
    const installerUrl = new URL(adminUrl!);
    installerUrl.username = 'openpc_root_expiry_scope_installer';
    installerUrl.password = randomBytes(24).toString('hex');
    await writeFile(
      join(scratch, 'root-expiry-initial-installer.private.json'),
      JSON.stringify({ databaseUrl: installerUrl.href }) + '\n',
      { mode: 0o600, flag: 'wx' },
    );
    let admin = new Pool({ connectionString: adminUrl, max: 3 });
    const installer = new Pool({ connectionString: installerUrl.href, max: 1 });
    const runtime = new Pool({ connectionString: runtimeUrl, max: 1 });
    const closed = new Set<Pool>();
    const end = async (pool: Pool) => {
      if (!closed.has(pool)) {
        closed.add(pool);
        await pool.end();
      }
    };
    try {
      await admin.query(
        `create role openpc_root_expiry_scope_installer login noinherit nosuperuser nocreatedb nocreaterole noreplication nobypassrls password '${installerUrl.password}'`,
      );
      await admin.query('grant openpc_control_owner to openpc_root_expiry_scope_installer');
      await admin.query(
        'grant connect on database openpc_control to openpc_root_expiry_scope_installer',
      );
      const verified = await verifyNativeRootExpiryReceivingTrust({
        admin,
        initialInstaller: installer,
        runtime,
        adminUrl: adminUrl!,
        operationsInput: await nativeRootExpiryInstallationInput(`expiry-${id().slice(-12)}`),
      });
      await Promise.all([end(admin), end(installer), end(runtime)]);
      await execute('docker', ['restart', target.id], { timeout: 60000, maxBuffer: 4096 });
      await execute(
        'docker',
        [
          'exec',
          target.id,
          'sh',
          '-c',
          'for n in $(seq 1 60); do pg_isready -h 127.0.0.1 -U postgres -d openpc_control >/dev/null 2>&1 && exit 0; sleep 0.1; done; exit 1',
        ],
        { timeout: 15000, maxBuffer: 4096 },
      );
      const published = await execute('docker', ['port', target.id, '5432/tcp'], {
        timeout: 10000,
        maxBuffer: 4096,
      });
      const match = /^127\.0\.0\.1:([0-9]+)$/u.exec(published.stdout.trim());
      expect(match).not.toBeNull();
      const restarted = new URL(adminUrl!);
      restarted.port = match![1]!;
      admin = new Pool({ connectionString: restarted.href, max: 2 });
      await verified.afterRestart(admin, match![1]!);
    } finally {
      await Promise.all([end(admin), end(installer), end(runtime)]);
    }
  },
  120000,
);
