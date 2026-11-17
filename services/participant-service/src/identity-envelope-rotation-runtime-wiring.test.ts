import { createHash } from 'node:crypto';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import {
  buildLocalParticipantRuntime,
  type LocalParticipantRuntimeConfig,
} from './local-runtime.js';

const wiring = vi.hoisted(() => ({
  hooks: new Map<string, Array<() => Promise<void>>>(),
  runOnce: vi.fn(async () => false),
  store: vi.fn(),
  worker: vi.fn(),
  signing: vi.fn(),
  rotation: vi.fn(),
  signingClose: vi.fn(),
  rotationClose: vi.fn(),
  log: vi.fn(),
  ready: vi.fn(),
  san: 'URI:urn:openpc:participant:01990000-0000-7000-8000-000000000001:workload:01990000-0000-7000-8000-000000000002',
}));
vi.mock('node:crypto', async (original) => ({
  ...(await original<typeof import('node:crypto')>()),
  X509Certificate: class {
    readonly subjectAltName = wiring.san;
    readonly publicKey = { export: () => Buffer.from('installed-spki') };
  },
}));
vi.mock('node:fs/promises', () => ({ readFile: vi.fn(async (path: string) => Buffer.from(path)) }));
vi.mock('pg', async () => {
  const { EventEmitter } = await import('node:events');
  return { Pool: class extends EventEmitter {} };
});
vi.mock('./app.js', () => ({
  buildPostgresParticipantService: vi.fn(() => ({
    addHook: (name: string, hook: () => Promise<void>) => {
      wiring.hooks.set(name, [...(wiring.hooks.get(name) ?? []), hook]);
    },
    get: (path: string, handler: unknown) => {
      if (path === '/readyz') wiring.ready.mockImplementation(handler as never);
    },
    log: { error: wiring.log },
  })),
}));
vi.mock('./identity-envelope-rotation-store.js', () => ({
  PostgresIdentityEnvelopeRotationAttemptStore: class {
    constructor(...args: unknown[]) {
      wiring.store(...args);
    }
  },
}));
vi.mock('./identity-envelope-rotation-worker.js', () => ({
  IdentityEnvelopeRotationWorker: class {
    constructor(...args: unknown[]) {
      wiring.worker(...args);
    }
    runOnce = wiring.runOnce;
  },
}));
vi.mock('../../identity-service/src/domain/http-identity-envelope-signing-provider.js', () => ({
  createHttpIdentityEnvelopeSigningProvider: (input: unknown) => {
    wiring.signing(input);
    return { close: wiring.signingClose };
  },
}));
vi.mock('../../identity-service/src/domain/http-identity-envelope-rotation-provider.js', () => ({
  createHttpIdentityEnvelopeRotationProvider: (input: unknown) => {
    wiring.rotation(input);
    return { close: wiring.rotationClose };
  },
}));

const config: LocalParticipantRuntimeConfig = {
  OPENPC_LOCAL_RUNTIME: '1',
  PARTICIPANT_DATABASE_HOST: 'database',
  PARTICIPANT_DATABASE_PORT: 5432,
  PARTICIPANT_DATABASE_NAME: 'openpc_local',
  PARTICIPANT_DATABASE_USER: 'openpc_participant_runtime',
  PARTICIPANT_DATABASE_PASSWORD_FILE: '/installed/database-password',
  databasePassword: 'd'.repeat(32),
  PARTICIPANT_IDENTITY_URL: 'http://identity:3001',
  PARTICIPANT_IDENTITY_INTERNAL_TOKEN_FILE: '/installed/identity-token',
  identityInternalToken: 'i'.repeat(32),
  PARTICIPANT_LOCAL_PRIVACY_DOMAIN_ID: '01990000-0000-7000-8000-000000000003',
  PARTICIPANT_ENVELOPE_SIGNING_PROVIDER_URL: 'https://provider.invalid',
  PARTICIPANT_ENVELOPE_SIGNING_PROVIDER_CA_FILE: '/installed/provider-ca',
  PARTICIPANT_ENVELOPE_SIGNING_PROVIDER_CERT_FILE: '/installed/client-cert',
  PARTICIPANT_ENVELOPE_SIGNING_PROVIDER_KEY_FILE: '/installed/client-key',
  PARTICIPANT_ENVELOPE_SIGNING_PROVIDER_SERVER_CERT_FILE: '/installed/server-cert',
  PARTICIPANT_ENVELOPE_SIGNING_ENVIRONMENT_ID: 'local',
  PARTICIPANT_ENVELOPE_SIGNING_CALLER_CREDENTIAL_ID: '01990000-0000-7000-8000-000000000004',
  PARTICIPANT_LISTEN: '0.0.0.0:3005',
};

beforeEach(() => {
  vi.clearAllMocks();
  vi.useFakeTimers();
  wiring.hooks.clear();
  wiring.san =
    'URI:urn:openpc:participant:01990000-0000-7000-8000-000000000001:workload:01990000-0000-7000-8000-000000000002';
});
afterEach(() => vi.useRealTimers());
async function hook(name: string) {
  for (const callback of wiring.hooks.get(name) ?? []) await callback();
}

it('leaves rotation disabled until installed configuration explicitly enables it', async () => {
  await buildLocalParticipantRuntime(config);
  await hook('onReady');
  await vi.advanceTimersByTimeAsync(10000);
  expect(wiring.rotation).not.toHaveBeenCalled();
  expect(wiring.store).not.toHaveBeenCalled();
  expect(wiring.runOnce).not.toHaveBeenCalled();
  await hook('onClose');
  expect(wiring.signingClose).toHaveBeenCalledTimes(1);
});

it('connects the scoped runtime pool and same installed pinned transport only after readiness', async () => {
  const { pool } = await buildLocalParticipantRuntime({
    ...config,
    PARTICIPANT_ENVELOPE_ROTATION_ENABLED: '1',
  });
  expect(wiring.rotation).toHaveBeenCalledExactlyOnceWith(wiring.signing.mock.calls[0]![0]);
  expect(wiring.store).toHaveBeenCalledExactlyOnceWith(pool, {
    participantId: '01990000-0000-7000-8000-000000000001',
    privacyDomainId: config.PARTICIPANT_LOCAL_PRIVACY_DOMAIN_ID,
    environmentId: 'local',
    callerWorkloadCredentialId: config.PARTICIPANT_ENVELOPE_SIGNING_CALLER_CREDENTIAL_ID,
    callerWorkloadKeyDigest:
      'sha256:' + createHash('sha256').update('installed-spki').digest('hex'),
  });
  expect(wiring.runOnce).not.toHaveBeenCalled();
  await hook('onReady');
  await vi.advanceTimersByTimeAsync(0);
  expect(wiring.runOnce).toHaveBeenCalledTimes(1);
  await hook('onClose');
  await vi.advanceTimersByTimeAsync(10000);
  expect(wiring.runOnce).toHaveBeenCalledTimes(1);
  expect(wiring.rotationClose).toHaveBeenCalledTimes(1);
  expect(wiring.signingClose).toHaveBeenCalledTimes(1);
});

it('fails incomplete installed configuration before constructing providers or workers', async () => {
  await expect(
    buildLocalParticipantRuntime({
      ...config,
      PARTICIPANT_ENVELOPE_ROTATION_ENABLED: '1',
      PARTICIPANT_ENVELOPE_SIGNING_PROVIDER_KEY_FILE: undefined,
    }),
  ).rejects.toThrow('incomplete local envelope signing configuration');
  expect(wiring.rotation).not.toHaveBeenCalled();
  expect(wiring.signing).not.toHaveBeenCalled();
  expect(wiring.store).not.toHaveBeenCalled();
});

it('rejects ambiguous certificate scope before providers or queue discovery', async () => {
  wiring.san += ', DNS:other.invalid';
  await expect(
    buildLocalParticipantRuntime({ ...config, PARTICIPANT_ENVELOPE_ROTATION_ENABLED: '1' }),
  ).rejects.toThrow('invalid installed envelope rotation identity');
  expect(wiring.rotation).not.toHaveBeenCalled();
  expect(wiring.signing).not.toHaveBeenCalled();
  expect(wiring.store).not.toHaveBeenCalled();
});

it('reports one redacted stopped event on worker failure and closes both transport owners', async () => {
  wiring.runOnce.mockRejectedValueOnce(new Error('private key and request'));
  await buildLocalParticipantRuntime({ ...config, PARTICIPANT_ENVELOPE_ROTATION_ENABLED: '1' });
  await hook('onReady');
  await vi.advanceTimersByTimeAsync(10000);
  expect(wiring.runOnce).toHaveBeenCalledTimes(1);
  expect(wiring.log).toHaveBeenCalledExactlyOnceWith({
    event: 'identity_envelope_rotation_worker_stopped',
  });
  const reply = { code: vi.fn(), send: vi.fn() };
  reply.code.mockReturnValue(reply);
  await wiring.ready(undefined, reply);
  expect(reply.code).toHaveBeenCalledExactlyOnceWith(503);
  expect(reply.send).toHaveBeenCalledExactlyOnceWith({ status: 'unavailable' });
  await hook('onClose');
  expect(wiring.rotationClose).toHaveBeenCalledTimes(1);
});
