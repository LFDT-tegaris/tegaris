import { beforeEach, expect, it, vi } from 'vitest';
import { open } from 'node:fs/promises';
import { generateKeyPairSync } from 'node:crypto';
import { Pool } from 'pg';
import {
  installPlatformRecoveryEnrollment,
  installDiscoveryCertificateRecoveryEnrollment,
  parsePlatformRecoveryEnrollmentArguments,
  readPlatformRecoveryDatabaseUrl,
  provisionPlatformRecoveryInstallationLogin,
  validatePlatformRecoveryInstallationPeer,
  runRecoveryEnrollmentInstallation,
} from '../../../../scripts/operations/installation-platform-recovery.mjs';
import { enrollPlatformRecovery } from './platform-recovery-enrollment.js';
import {
  trustFixture as discoveryFixture,
  rootExpiryTrustFixture as discoveryRootFixture,
} from '../domain/discovery-certificate-recovery.test-fixture.js';
import {
  platformRecoveryFixture,
  rootExpiryPlatformRecoveryFixture,
  pendingPlatformRecoveryFixture,
} from '../domain/platform-recovery.test-fixture.js';
import { identityEnvelopeRecoveryFixture } from '../domain/identity-envelope-recovery.test-fixture.js';
import { localRootExpiryRecoveryFixture } from '../domain/local-root-expiry-recovery.test-fixture.js';
import {
  installRootExpiryRecoveryTrust,
  enrollRootExpiryRecovery,
} from './root-expiry-recovery-installation.js';
import {
  installIdentityEnvelopeRecoveryReceivingTrust,
  enrollIdentityEnvelopeRecovery,
} from './identity-envelope-recovery-enrollment.js';

vi.mock('./platform-recovery-enrollment.js', () => ({ enrollPlatformRecovery: vi.fn() }));
vi.mock('./root-expiry-recovery-installation.js', () => ({
  installRootExpiryRecoveryTrust: vi.fn(),
  enrollRootExpiryRecovery: vi.fn(),
}));
vi.mock('pg', () => ({ Pool: vi.fn() }));
vi.mock('./identity-envelope-recovery-enrollment.js', () => ({
  installIdentityEnvelopeRecoveryReceivingTrust: vi.fn(),
  enrollIdentityEnvelopeRecovery: vi.fn(),
}));
vi.mock('node:fs/promises', async (original) => ({
  ...(await original<typeof import('node:fs/promises')>()),
  open: vi.fn(),
}));
beforeEach(() => vi.resetAllMocks());

it.each(['trust', 'enrollment'])(
  'passes the independently installed verifier to the V3 Root %s owner',
  async (kind) => {
    const f = localRootExpiryRecoveryFixture();
    const v = setup();
    const input =
      kind === 'trust'
        ? { ...f.trust, schemaVersion: 3 }
        : {
            document: { ...f.enrollment, schemaVersion: 3 },
            signature: f.signed.signature,
          };
    const verifier = { verifyCanonicalAssertion: vi.fn() };
    const owner = kind === 'trust' ? installRootExpiryRecoveryTrust : enrollRootExpiryRecovery;
    vi.mocked(owner).mockResolvedValue(v.result as never);
    await expect(
      installPlatformRecoveryEnrollment(v.pool, input, {
        localQaEnabled: true,
        identityRuntimeVerifier: verifier,
      }),
    ).resolves.toEqual(v.result);
    expect(owner).toHaveBeenCalledWith(v.client, input, true, verifier);
    expect(v.statements.at(-1)).toBe('commit');
    expect(enrollPlatformRecovery).not.toHaveBeenCalled();
  },
);

it.each(['trust', 'enrollment'])(
  'rejects missing independent V3 Root %s trust before opening an installation transaction',
  async (kind) => {
    const f = localRootExpiryRecoveryFixture();
    const v = setup();
    const input =
      kind === 'trust'
        ? { ...f.trust, schemaVersion: 3 }
        : {
            document: { ...f.enrollment, schemaVersion: 3 },
            signature: f.signed.signature,
          };
    await expect(
      installPlatformRecoveryEnrollment(v.pool, input, { localQaEnabled: true }),
    ).rejects.toThrow(/OPS_CONFIG_INVALID/u);
    expect(v.statements).toEqual([]);
    expect(installRootExpiryRecoveryTrust).not.toHaveBeenCalled();
    expect(enrollRootExpiryRecovery).not.toHaveBeenCalled();
  },
);

it('admits only separately typed signer repair trust and signed custody through the existing host entrypoint', async () => {
  const f = identityEnvelopeRecoveryFixture();
  for (const input of [f.trust, f.signed]) {
    const v = setup();
    const result = { authority: 'NONE' as const, state: 'ENROLLED' as const };
    vi.mocked(installIdentityEnvelopeRecoveryReceivingTrust).mockResolvedValue(result as never);
    vi.mocked(enrollIdentityEnvelopeRecovery).mockResolvedValue(result as never);
    expect(
      await installPlatformRecoveryEnrollment(v.pool, input, { localQaEnabled: true }),
    ).toEqual(result);
    expect(v.statements.at(-1)).toBe('commit');
    expect(enrollPlatformRecovery).not.toHaveBeenCalled();
    if ('document' in input) {
      expect(enrollIdentityEnvelopeRecovery).toHaveBeenCalledWith(v.client, input, {
        localQaEnabled: true,
      });
      expect(installIdentityEnvelopeRecoveryReceivingTrust).not.toHaveBeenCalled();
    } else {
      expect(installIdentityEnvelopeRecoveryReceivingTrust).toHaveBeenCalledWith(v.client, input, {
        localQaEnabled: true,
      });
      expect(enrollIdentityEnvelopeRecovery).not.toHaveBeenCalled();
    }
    vi.clearAllMocks();
  }
});

it('denies signer custody installation by an inadmissible owner before invoking its trust adapter', async () => {
  const f = identityEnvelopeRecoveryFixture();
  const v = setup('account');
  await expect(
    installPlatformRecoveryEnrollment(v.pool, f.signed, { localQaEnabled: true }),
  ).rejects.toThrow(/OPS_CONFIG_INVALID/u);
  expect(enrollIdentityEnvelopeRecovery).not.toHaveBeenCalled();
  expect(v.statements.at(-1)).toBe('rollback');
});

it('rolls back provisional signed custody when an exact source read fails', async () => {
  const f = identityEnvelopeRecoveryFixture();
  const v = setup();
  vi.mocked(enrollIdentityEnvelopeRecovery).mockImplementationOnce(async (client) => {
    await client.query(
      'insert into control.identity_envelope_recovery_enrollment /* provisional */',
    );
    throw Object.assign(new Error('private source diagnostic'), { code: '42501' });
  });
  await expect(
    installPlatformRecoveryEnrollment(v.pool, f.signed, { localQaEnabled: true }),
  ).rejects.toThrow(/OPS_CONFIG_INVALID/u);
  expect(v.statements).toContain(
    'insert into control.identity_envelope_recovery_enrollment /* provisional */',
  );
  expect(v.statements).not.toContain('commit');
  expect(v.statements.at(-1)).toBe('rollback');
  expect(v.release).toHaveBeenCalledOnce();
});

function setup(failure?: 'account' | 'participant' | 'privacy' | 'source' | 'commit') {
  const statements: string[] = [];
  const query = vi.fn(async (sql: string) => {
    statements.push(sql);
    if (sql === 'commit' && failure === 'commit') throw new Error('private database diagnostic');
    if (sql.includes('pg_has_role'))
      return { rows: [{ allowed: failure !== 'account' }], rowCount: 1 };
    if (sql.includes('from control.participant'))
      return { rowCount: failure === 'participant' ? 0 : 1 };
    if (sql.includes('from control.privacy_domain'))
      return { rowCount: failure === 'privacy' ? 0 : 1 };
    return { rows: [], rowCount: 0 };
  });
  const release = vi.fn();
  const client = { query, release };
  const pool = { connect: vi.fn().mockResolvedValue(client) } as never;
  const enrollment = platformRecoveryFixture().source.enrollment;
  const result = { state: 'ENROLLED', authority: 'NONE' };
  if (failure === 'source')
    vi.mocked(enrollPlatformRecovery).mockRejectedValue(new Error('private source diagnostic'));
  else vi.mocked(enrollPlatformRecovery).mockResolvedValue(result as never);
  return { statements, client, release, pool, enrollment, result };
}

it.each(['root expiry', 'pending continuation'])(
  'passes independent receipt trust and explicit local context for %s through the existing installation owner',
  async (kind) => {
    const v = setup();
    const enrollment = (
      kind === 'root expiry'
        ? rootExpiryPlatformRecoveryFixture()
        : pendingPlatformRecoveryFixture()
    ).source.enrollment;
    const verifier = { verifyCanonicalAssertion: vi.fn() };
    await expect(
      installPlatformRecoveryEnrollment(v.pool, enrollment, {
        localQaEnabled: true,
        identityRuntimeVerifier: verifier,
      }),
    ).resolves.toEqual(v.result);
    expect(enrollPlatformRecovery).toHaveBeenCalledWith(v.client, enrollment, {
      localQaEnabled: true,
      verifier,
    });
    expect(v.statements).toContain("select set_config('openpc.local_qa_runtime','1',true)");
    expect(v.statements.at(-1)).toBe('commit');
  },
);
it.each([
  ['root expiry', 'local profile'],
  ['root expiry', 'receipt verifier'],
  ['pending continuation', 'local profile'],
  ['pending continuation', 'receipt verifier'],
])('denies %s missing %s before source enrollment', async (kind, missing) => {
  const v = setup();
  const enrollment = (
    kind === 'root expiry' ? rootExpiryPlatformRecoveryFixture() : pendingPlatformRecoveryFixture()
  ).source.enrollment;
  const verifier = { verifyCanonicalAssertion: vi.fn() };
  await expect(
    installPlatformRecoveryEnrollment(v.pool, enrollment, {
      localQaEnabled: missing !== 'local profile',
      ...(missing === 'receipt verifier' ? {} : { identityRuntimeVerifier: verifier }),
    }),
  ).rejects.toThrow(/OPS_CONFIG_INVALID/u);
  expect(enrollPlatformRecovery).not.toHaveBeenCalled();
  expect(v.statements).toEqual([]);
});

it.each([
  'pending continuation',
  'Root trust V3',
  'Root enrollment V3',
  'Root trust V2',
  'Root enrollment V2',
  'foreign discovery version',
  'unknown platform version',
])('routes host independent trust only for the owning schema: %s', async (kind) => {
  const v = setup(),
    enrollment = structuredClone(pendingPlatformRecoveryFixture().source.enrollment);
  const rootFixture = localRootExpiryRecoveryFixture();
  const rootVersion = kind.endsWith('V2') ? 2 : 3;
  const input = kind.startsWith('Root trust')
    ? { ...rootFixture.trust, schemaVersion: rootVersion }
    : kind.startsWith('Root enrollment')
      ? {
          document: { ...rootFixture.enrollment, schemaVersion: rootVersion },
          signature: rootFixture.signed.signature,
        }
      : kind === 'foreign discovery version'
        ? { ...enrollment, schema: 'pc.identity.discovery-certificate-recovery-enrollment' }
        : kind === 'unknown platform version'
          ? { ...enrollment, schemaVersion: 5 }
          : enrollment;
  const trusted = generateKeyPairSync('ed25519').publicKey.export({
    type: 'spki',
    format: 'der',
  });
  const files: Record<string, Buffer> = {
    '/private/enrollment.json': Buffer.from(JSON.stringify(input)),
    '/private/trust.der': trusted,
    '/private/database.url': Buffer.from('postgresql://installer:synthetic@localhost/openpc'),
  };
  vi.mocked(open).mockImplementation(async (path) => {
    const bytes = files[String(path)];
    if (!bytes) throw new Error('unexpected private input');
    let cursor = 0;
    return {
      stat: async () => ({
        isFile: () => true,
        uid: process.getuid!(),
        mode: 0o600,
        size: bytes.length,
      }),
      read: async (buffer: Buffer, offset: number, length: number, position: number | null) => {
        const start = position ?? cursor,
          count = Math.min(length, bytes.length - start);
        bytes.copy(buffer, offset, start, start + count);
        cursor = start + count;
        return { bytesRead: count };
      },
      close: vi.fn(),
    } as never;
  });
  const end = vi.fn();
  vi.mocked(Pool).mockImplementation(function () {
    return { ...(v.pool as object), end };
  } as never);
  const install = vi.fn().mockResolvedValue(v.result);
  const stdout = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
  const stderr = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
  const originalArgv = process.argv,
    originalExit = process.exitCode;
  process.argv = [
    process.execPath,
    '/host/installation-platform-recovery.mjs',
    '--enrollment',
    '/private/enrollment.json',
    '--database-url-file',
    '/private/database.url',
    '--identity-runtime-trust-file',
    '/private/trust.der',
    '--local-qa-virtual-authenticator',
  ];
  process.exitCode = undefined;
  try {
    await runRecoveryEnrollmentInstallation(install);
    if (
      kind === 'pending continuation' ||
      kind === 'Root trust V3' ||
      kind === 'Root enrollment V3'
    ) {
      expect(install).toHaveBeenCalledOnce();
      expect(install).toHaveBeenCalledWith(
        expect.anything(),
        input,
        expect.objectContaining({
          localQaEnabled: true,
          identityRuntimeVerifier: expect.objectContaining({
            verifyCanonicalAssertion: expect.any(Function),
          }),
        }),
      );
      expect(process.exitCode).toBeUndefined();
      expect(stderr).not.toHaveBeenCalled();
      expect(end).toHaveBeenCalledOnce();
    } else {
      expect(install).not.toHaveBeenCalled();
      expect(Pool).not.toHaveBeenCalled();
      expect(process.exitCode).toBe(2);
      expect(stdout).not.toHaveBeenCalled();
      expect(stderr).toHaveBeenCalledWith(
        expect.stringContaining('PLATFORM_RECOVERY_ENROLLMENT_UNAVAILABLE'),
      );
    }
  } finally {
    process.argv = originalArgv;
    process.exitCode = originalExit;
    stdout.mockRestore();
    stderr.mockRestore();
  }
});

it('installs initial trust under the least-privilege account and Participant write fence', async () => {
  const v = setup();
  expect(
    await installPlatformRecoveryEnrollment(v.pool, v.enrollment, { localQaEnabled: true }),
  ).toEqual(v.result);
  expect(v.statements[0]).toBe('begin isolation level read committed');
  expect(v.statements[1]).toBe('set local role openpc_control_owner');
  expect(v.statements.findIndex((sql) => sql.includes('pg_has_role'))).toBeLessThan(
    v.statements.findIndex((sql) => sql.includes('from control.participant')),
  );
  expect(v.statements.find((sql) => sql.includes('from control.participant'))).toMatch(
    /for update/u,
  );
  expect(enrollPlatformRecovery).toHaveBeenCalledWith(v.client, v.enrollment, {
    localQaEnabled: true,
  });
  expect(v.statements).toContain(
    `select set_config('openpc.action_intent_id','ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',true)`,
  );
  expect(v.statements.at(-1)).toBe('commit');
  expect(v.statements.some((sql) => /^(insert|update|delete)\s/iu.test(sql))).toBe(false);
  expect(v.release).toHaveBeenCalledOnce();
});

it.each(['account', 'participant', 'privacy', 'source', 'commit'] as const)(
  'rolls back %s without disclosing diagnostics',
  async (failure) => {
    const v = setup(failure);
    await expect(installPlatformRecoveryEnrollment(v.pool, v.enrollment)).rejects.toThrow(
      /OPS_CONFIG_INVALID/u,
    );
    expect(v.statements.at(-1)).toBe('rollback');
    expect(v.release).toHaveBeenCalledOnce();
    if (['account', 'participant', 'privacy'].includes(failure))
      expect(enrollPlatformRecovery).not.toHaveBeenCalled();
  },
);

it('requires an explicit local QA option instead of inferring assurance from a fixture', async () => {
  const v = setup();
  await installPlatformRecoveryEnrollment(v.pool, v.enrollment);
  expect(enrollPlatformRecovery).toHaveBeenCalledWith(v.client, v.enrollment, {
    localQaEnabled: false,
  });
});

it('accepts private file references without credentials on argv', () => {
  expect(
    parsePlatformRecoveryEnrollmentArguments([
      '--enrollment',
      '/private/enrollment.json',
      '--database-url-file',
      '/private/database.url',
      '--local-qa-virtual-authenticator',
    ]),
  ).toMatchObject({ localQaEnabled: true });
});
it('accepts one independent installed runtime trust file and rejects duplicate or relative references', () => {
  const base = [
    '--enrollment',
    '/private/enrollment.json',
    '--database-url-file',
    '/private/database.url',
  ];
  expect(
    parsePlatformRecoveryEnrollmentArguments([
      ...base,
      '--identity-runtime-trust-file',
      '/private/runtime.spki',
    ]),
  ).toMatchObject({ '--identity-runtime-trust-file': '/private/runtime.spki' });
  expect(() =>
    parsePlatformRecoveryEnrollmentArguments([
      ...base,
      '--identity-runtime-trust-file',
      'runtime.spki',
    ]),
  ).toThrow();
  expect(() =>
    parsePlatformRecoveryEnrollmentArguments([
      ...base,
      '--identity-runtime-trust-file',
      '/private/runtime.spki',
      '--identity-runtime-trust-file',
      '/private/other.spki',
    ]),
  ).toThrow();
});
it('forwards independently installed verification trust to the signed enrollment owner', async () => {
  const f = identityEnvelopeRecoveryFixture(),
    v = setup();
  const verifier = { verifyCanonicalAssertion: vi.fn() };
  vi.mocked(enrollIdentityEnvelopeRecovery).mockResolvedValue({
    state: 'ENROLLED',
    authority: 'NONE',
  } as never);
  await installPlatformRecoveryEnrollment(v.pool, f.signed, {
    localQaEnabled: true,
    identityRuntimeVerifier: verifier,
  });
  expect(enrollIdentityEnvelopeRecovery).toHaveBeenCalledWith(v.client, f.signed, {
    localQaEnabled: true,
    identityRuntimeVerifier: verifier,
  });
});
it.each(
  [
    ['--enrollment', 'relative.json', '--database-url-file', '/private/database.url'],
    ['--enrollment', '/private/enrollment.json'],
    ['--database-url', 'postgres://private'],
    [
      '--enrollment',
      '/private/a',
      '--enrollment',
      '/private/b',
      '--database-url-file',
      '/private/database.url',
    ],
    [
      '--enrollment',
      '/private/a',
      '--database-url-file',
      '/private/database.url',
      '--local-qa-virtual-authenticator',
      '--local-qa-virtual-authenticator',
    ],
  ].map((args) => ({ args })),
)('rejects unsupported or ambiguous host invocation $args', ({ args }) => {
  expect(() => parsePlatformRecoveryEnrollmentArguments(args)).toThrow(
    /PLATFORM_RECOVERY_ENROLLMENT_UNAVAILABLE/u,
  );
});

function privateFile(failure?: string) {
  const bytes = Buffer.from(
    failure === 'scheme'
      ? 'https://private.invalid/'
      : 'postgresql://installer:synthetic@localhost/openpc',
  );
  const close = vi.fn();
  vi.mocked(open).mockResolvedValue({
    stat: async () => ({
      isFile: () => failure !== 'device',
      uid: failure === 'owner' ? process.getuid!() + 1 : process.getuid!(),
      mode: failure === 'permissions' ? 0o644 : 0o600,
      size: failure === 'size' ? 8193 : bytes.length,
    }),
    read: async (buffer: Buffer) => {
      bytes.copy(buffer);
      return { bytesRead: bytes.length };
    },
    close,
  } as never);
  return { bytes, close };
}
it('loads a bounded private database reference and closes its descriptor', async () => {
  const v = privateFile();
  expect(await readPlatformRecoveryDatabaseUrl('/private/database.url')).toBe(v.bytes.toString());
  expect(v.close).toHaveBeenCalledOnce();
});
it.each(['owner', 'permissions', 'device', 'size', 'scheme'])(
  'rejects unsafe private database input: %s',
  async (failure) => {
    const v = privateFile(failure);
    await expect(readPlatformRecoveryDatabaseUrl('/private/database.url')).rejects.toThrow(
      'PLATFORM_RECOVERY_ENROLLMENT_UNAVAILABLE',
    );
    expect(v.close).toHaveBeenCalledOnce();
  },
);

it('keeps installation purposes separate and installs only initial discovery trust under the same owner fences', async () => {
  const v = setup();
  const enrollment = discoveryFixture().source.enrollment;
  await expect(
    installPlatformRecoveryEnrollment(v.pool, enrollment, { localQaEnabled: true }),
  ).rejects.toThrow();
  expect((v.pool as { connect: ReturnType<typeof vi.fn> }).connect).not.toHaveBeenCalled();
  await expect(
    installDiscoveryCertificateRecoveryEnrollment(v.pool, v.enrollment, { localQaEnabled: true }),
  ).rejects.toThrow();
  expect((v.pool as { connect: ReturnType<typeof vi.fn> }).connect).not.toHaveBeenCalled();
  await expect(
    installDiscoveryCertificateRecoveryEnrollment(v.pool, enrollment, { localQaEnabled: true }),
  ).resolves.toEqual(v.result);
  expect(enrollPlatformRecovery).toHaveBeenCalledWith(expect.anything(), enrollment, {
    localQaEnabled: true,
  });
  expect(
    v.statements.some((sql) =>
      /insert into control\.(credential|authority_envelope|assignment|approval_request)/u.test(sql),
    ),
  ).toBe(false);
});

it.each(['complete', 'QA absent', 'verifier absent'])(
  'keeps receipt discovery installation trust explicit: %s',
  async (state) => {
    const v = setup();
    const enrollment = discoveryRootFixture().source.enrollment;
    const verifier = { verifyCanonicalAssertion: vi.fn() };
    const options = {
      localQaEnabled: state !== 'QA absent',
      ...(state === 'verifier absent' ? {} : { identityRuntimeVerifier: verifier }),
    };
    if (state !== 'complete') {
      await expect(
        installDiscoveryCertificateRecoveryEnrollment(v.pool, enrollment, options),
      ).rejects.toThrow(/OPS_CONFIG_INVALID/u);
      expect(v.statements).toEqual([]);
      expect(enrollPlatformRecovery).not.toHaveBeenCalled();
      return;
    }
    await expect(
      installDiscoveryCertificateRecoveryEnrollment(v.pool, enrollment, options),
    ).resolves.toEqual(v.result);
    expect(enrollPlatformRecovery).toHaveBeenCalledWith(v.client, enrollment, {
      localQaEnabled: true,
      verifier,
    });
    expect(v.statements).toContain("select set_config('openpc.local_qa_runtime','1',true)");
    expect(v.statements.at(-1)).toBe('commit');
  },
);

const desiredInstallationUrl =
  'postgresql://openpc_recovery_installation:' + 'a'.repeat(64) + '@127.0.0.1:5432/openpc_control';
const bootstrapInstallationUrl =
  'postgresql://openpc_control:' + 'b'.repeat(64) + '@127.0.0.1:5432/openpc_control';
it('admits opt-in owner login provisioning only with a separate protected bootstrap URL file', () => {
  expect(
    parsePlatformRecoveryEnrollmentArguments([
      '--enrollment',
      '/private/receiving.json',
      '--database-url-file',
      '/private/installation.url',
      '--provision-installation-login',
      '--bootstrap-database-url-file',
      '/private/bootstrap.url',
    ]),
  ).toMatchObject({
    'provisionInstallationLogin': true,
    '--bootstrap-database-url-file': '/private/bootstrap.url',
  });
  expect(() =>
    validatePlatformRecoveryInstallationPeer(bootstrapInstallationUrl, desiredInstallationUrl),
  ).not.toThrow();
});
it.each([
  [
    '--enrollment',
    '/private/receiving.json',
    '--database-url-file',
    '/private/installation.url',
    '--provision-installation-login',
  ],
  [
    '--enrollment',
    '/private/receiving.json',
    '--database-url-file',
    '/private/installation.url',
    '--bootstrap-database-url-file',
    '/private/bootstrap.url',
  ],
  [
    '--enrollment',
    '/private/receiving.json',
    '--database-url-file',
    '/private/installation.url',
    '--provision-installation-login',
    '--provision-installation-login',
    '--bootstrap-database-url-file',
    '/private/bootstrap.url',
  ],
  [
    '--enrollment',
    '/private/receiving.json',
    '--database-url-file',
    '/private/installation.url',
    '--provision-installation-login',
    '--bootstrap-database-url-file',
    'postgresql://private',
  ],
])('denies unpaired/duplicate/raw-credential provisioning input %s', (...args: string[]) => {
  expect(() => parsePlatformRecoveryEnrollmentArguments(args)).toThrow(/OPS_CONFIG_INVALID/u);
});
it.each(['host', 'port', 'database', 'tls', 'target-login', 'missing-bootstrap-password'] as const)(
  'denies %s peer substitution before role bootstrap',
  (kind) => {
    const target = new URL(desiredInstallationUrl),
      initial = new URL(bootstrapInstallationUrl);
    if (kind === 'host') target.hostname = 'foreign.invalid';
    if (kind === 'port') target.port = '5433';
    if (kind === 'database') target.pathname = '/foreign';
    if (kind === 'tls') target.search = '?sslmode=disable';
    if (kind === 'target-login') target.username = 'openpc_control';
    if (kind === 'missing-bootstrap-password') initial.password = '';
    expect(() =>
      validatePlatformRecoveryInstallationPeer(initial.toString(), target.toString()),
    ).toThrow(/OPS_CONFIG_INVALID/u);
  },
);
function loginSetup(failure?: 'authority' | 'role' | 'result' | 'commit', created = true) {
  const query = vi.fn(async (sql: string): Promise<{ rowCount: number; rows: unknown[] }> => {
    if (sql.startsWith('select current_database'))
      return { rowCount: 1, rows: [{ allowed: failure !== 'authority' }] };
    if (sql.startsWith('do $$') && failure === 'role') throw Error('private role diagnostic');
    if (sql.startsWith('select current_setting'))
      return { rowCount: failure === 'result' ? 0 : 1, rows: [{ created }] };
    if (sql === 'commit' && failure === 'commit') throw Error('private commit diagnostic');
    return { rowCount: 1, rows: [] };
  });
  const release = vi.fn(),
    connect = vi.fn(async () => ({ query, release })),
    pool = { connect } as never;
  return { query, release, connect, pool };
}
it.each([true, false])(
  'provisions or preserves the host-owned login, never enrolls or admits business authority (created=%s)',
  async (created) => {
    const f = loginSetup(undefined, created);
    expect(
      await provisionPlatformRecoveryInstallationLogin(f.pool, desiredInstallationUrl),
    ).toEqual({
      login: 'openpc_recovery_installation',
      created,
      authority: 'INSTALLATION_ONLY',
      ownership: 'openpc:installation-recovery-login:v1',
    });
    expect(f.query.mock.calls.at(-1)?.[0]).toBe('commit');
    expect(f.release).toHaveBeenCalledOnce();
    const roleSql = f.query.mock.calls.find(([sql]) => sql.startsWith('do $$'))?.[0] ?? '';
    expect(roleSql).toContain('GRANT CONNECT ON DATABASE %I TO openpc_recovery_installation');
    expect(roleSql.indexOf('GRANT CONNECT')).toBeGreaterThan(
      roleSql.indexOf("raise exception 'OPS_CONFIG_INVALID-INSTALLATION-LOGIN'"),
    );
    expect(roleSql).not.toMatch(/GRANT (?:CREATE|TEMP|ALL)|ALTER ROLE/u);
    expect(enrollPlatformRecovery).not.toHaveBeenCalled();
    expect(enrollIdentityEnvelopeRecovery).not.toHaveBeenCalled();
    expect(installIdentityEnvelopeRecoveryReceivingTrust).not.toHaveBeenCalled();
    expect(
      f.query.mock.calls.some(
        ([sql]) =>
          sql.includes('control.principal') ||
          sql.includes('control.credential') ||
          sql.includes('control.platform_recovery_case') ||
          sql.includes('control.business_signing_key'),
      ),
    ).toBe(false);
  },
);
it.each(['authority', 'role', 'result', 'commit'] as const)(
  'rolls back %s login bootstrap without exposing source diagnostics or resetting an existing password',
  async (failure) => {
    const f = loginSetup(failure);
    await expect(
      provisionPlatformRecoveryInstallationLogin(f.pool, desiredInstallationUrl),
    ).rejects.toThrow(/OPS_CONFIG_INVALID/u);
    expect(f.query.mock.calls.at(-1)?.[0]).toBe('rollback');
    expect(f.release).toHaveBeenCalledOnce();
    if (failure === 'authority')
      expect(f.query.mock.calls.some(([sql]) => sql.startsWith('do $$'))).toBe(false);
  },
);
it.each(['short-password', 'foreign-login', 'malformed-password', 'raw-newline'] as const)(
  'rejects %s target login before connecting',
  async (kind) => {
    const f = loginSetup();
    const url = new URL(desiredInstallationUrl);
    if (kind === 'short-password') url.password = 'short';
    if (kind === 'foreign-login') url.username = 'other';
    if (kind === 'malformed-password') url.password = '%aa';
    await expect(
      provisionPlatformRecoveryInstallationLogin(
        f.pool,
        url.toString() + (kind === 'raw-newline' ? '\n' : ''),
      ),
    ).rejects.toThrow(/OPS_CONFIG_INVALID/u);
    expect(f.connect).not.toHaveBeenCalled();
  },
);
