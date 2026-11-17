import { generateKeyPairSync } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it, vi } from 'vitest';
import { IdentityKernelError } from './domain/identity-errors.js';
import * as sessionContext from './domain/session-privacy-context.js';
import * as policyAuthorization from './domain/policy-authorization.js';

import {
  buildLocalIdentityRuntime,
  localPolicyAuthorizationResponse,
  localWebAuthnAllowedOrigin,
  readLocalIdentityRuntimeConfig,
  readLocalSigningContinuationCrypto,
  readLocalWorkloadIssuerCa,
  readLocalWorkloadIssuerProfile,
} from './local-runtime.js';

const roots: string[] = [];

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), 'openpc-identity-runtime-'));
  roots.push(root);
  const paths = {
    ca: join(root, 'ca'),
    database: join(root, 'database'),
    internal: join(root, 'internal'),
    workloadIssuerToken: join(root, 'workload-issuer-token'),
    operator: join(root, 'operator'),
    runtimePrivateKey: join(root, 'runtime-private-key'),
    runtimePublicKey: join(root, 'runtime-public-key'),
    serverCertificate: join(root, 'server-certificate'),
    serverKey: join(root, 'server-key'),
    viewer: join(root, 'viewer'),
  };
  const runtimeKey = generateKeyPairSync('ed25519');
  await Promise.all([
    ...Object.entries(paths)
      .filter(([name]) => name !== 'runtimePrivateKey' && name !== 'runtimePublicKey')
      .map(([, path]) => writeFile(path, 'a'.repeat(32))),
    writeFile(
      paths.runtimePrivateKey,
      runtimeKey.privateKey.export({ format: 'der', type: 'pkcs8' }),
    ),
    writeFile(paths.runtimePublicKey, runtimeKey.publicKey.export({ format: 'der', type: 'spki' })),
  ]);
  execFileSync(
    'openssl',
    [
      'req',
      '-x509',
      '-newkey',
      'ec',
      '-pkeyopt',
      'ec_paramgen_curve:P-256',
      '-nodes',
      '-keyout',
      join(root, 'ca-key'),
      '-out',
      paths.ca,
      '-subj',
      '/CN=OpenPC runtime unit fixture',
      '-days',
      '1',
    ],
    { stdio: 'ignore' },
  );
  return {
    paths,
    environment: {
      OPENPC_LOCAL_RUNTIME: '1',
      IDENTITY_DATABASE_HOST: '127.0.0.1',
      IDENTITY_DATABASE_PORT: '1',
      IDENTITY_DATABASE_NAME: 'openpc_control',
      IDENTITY_DATABASE_USER: 'openpc_identity_runtime',
      IDENTITY_DATABASE_PASSWORD_FILE: paths.database,
      IDENTITY_INTERNAL_TOKEN_FILE: paths.internal,
      IDENTITY_RUNTIME_SIGNING_PRIVATE_KEY_FILE: paths.runtimePrivateKey,
      IDENTITY_RUNTIME_SIGNING_PUBLIC_KEY_FILE: paths.runtimePublicKey,
      IDENTITY_RUNTIME_TRUSTED_PUBLIC_KEY_FILES: paths.runtimePublicKey,
      IDENTITY_LOCAL_OPERATOR_CREDENTIAL_FILE: paths.operator,
      IDENTITY_LOCAL_VIEWER_CREDENTIAL_FILE: paths.viewer,
      IDENTITY_LOCAL_OPERATOR_PRINCIPAL_ID: '018f0000-0000-7000-8000-000000000111',
      IDENTITY_LOCAL_VIEWER_PRINCIPAL_ID: '018f0000-0000-7000-8000-000000000112',
      IDENTITY_LOCAL_PARTICIPANT_ID: '018f0000-0000-7000-8000-000000000101',
      IDENTITY_LOCAL_PRIVACY_DOMAIN_ID: '018f0000-0000-7000-8000-000000000201',
      IDENTITY_OIDC_ISSUER: 'http://127.0.0.1:3006',
      IDENTITY_OIDC_CLIENT_ID: 'openpc-local-workbench',
      IDENTITY_OIDC_REDIRECT_URI: 'http://127.0.0.1:8080/api/v1/session/oidc/callback',
      IDENTITY_MTLS_CA_FILE: paths.ca,
      IDENTITY_WORKLOAD_ISSUER_URL: 'http://127.0.0.1:3007/v1/certificates',
      IDENTITY_WORKLOAD_ISSUER_TOKEN_FILE: paths.workloadIssuerToken,
      IDENTITY_MTLS_SERVER_CERT_FILE: paths.serverCertificate,
      IDENTITY_MTLS_SERVER_KEY_FILE: paths.serverKey,
      IDENTITY_MTLS_LISTEN: '0.0.0.0:3443',
      IDENTITY_LISTEN: '0.0.0.0:3001',
    },
  };
}

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe('local identity runtime boundary', () => {
  it('requires a complete explicit QA issuer profile and fails closed on missing installed inputs', async () => {
    const { environment, paths } = await fixture();
    const selected = {
      IDENTITY_WORKLOAD_ISSUER_LOCAL_PROFILE_FILE: join(paths.ca, '..', 'absent-profile'),
      IDENTITY_WORKLOAD_ISSUER_LOCAL_PROFILE_SHA256: 'a'.repeat(64),
    };
    for (const change of [
      {
        IDENTITY_WORKLOAD_ISSUER_LOCAL_PROFILE_FILE:
          selected.IDENTITY_WORKLOAD_ISSUER_LOCAL_PROFILE_FILE,
      },
      {
        IDENTITY_WORKLOAD_ISSUER_LOCAL_PROFILE_SHA256:
          selected.IDENTITY_WORKLOAD_ISSUER_LOCAL_PROFILE_SHA256,
      },
      selected,
      { ...selected, OPENPC_LOCAL_RUNTIME_QA_FIXTURE: '1' },
    ])
      await expect(readLocalIdentityRuntimeConfig({ ...environment, ...change })).rejects.toThrow();
    const config = await readLocalIdentityRuntimeConfig({
      ...environment,
      ...selected,
      OPENPC_LOCAL_RUNTIME_QA_FIXTURE: '1',
      IDENTITY_WORKLOAD_ISSUER_CA_FILE: paths.ca,
    });
    await expect(
      readLocalWorkloadIssuerProfile(config, await readFile(paths.ca)),
    ).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('defaults issuer verification to the installed transport CA', async () => {
    const { environment, paths } = await fixture();
    const config = await readLocalIdentityRuntimeConfig(environment);
    expect(await readLocalWorkloadIssuerCa(config)).toEqual(await readFile(paths.ca));
    expect(config.IDENTITY_WORKLOAD_ISSUER_CA_FILE).toBeUndefined();
  });

  it('reads explicit issuer trust separately and fails closed when that installation is missing', async () => {
    const { environment, paths } = await fixture();
    const issuerCa = join(paths.ca, '..', 'issuer-ca');
    await writeFile(issuerCa, 'separately installed issuer trust');
    const config = await readLocalIdentityRuntimeConfig({
      ...environment,
      IDENTITY_WORKLOAD_ISSUER_CA_FILE: issuerCa,
    });
    expect(await readLocalWorkloadIssuerCa(config)).toEqual(
      Buffer.from('separately installed issuer trust'),
    );
    expect(config.IDENTITY_MTLS_CA_FILE).toBe(paths.ca);
    await rm(issuerCa);
    await expect(readLocalWorkloadIssuerCa(config)).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(
      readLocalIdentityRuntimeConfig({ ...environment, IDENTITY_WORKLOAD_ISSUER_CA_FILE: '' }),
    ).rejects.toThrow();
  });

  it('keeps assertion-only session timing fields off the local authorization wire contract', () => {
    const response = localPolicyAuthorizationResponse({
      sessionId: '018f0000-0000-7000-8000-000000000001',
      sessionEpoch: '2',
      sessionIssuedAt: new Date('2026-09-11T01:00:00.000Z'),
      sessionIdleExpiresAt: new Date('2026-09-11T02:00:00.000Z'),
      sessionAbsoluteExpiresAt: new Date('2026-09-11T12:00:00.000Z'),
      participantId: '018f0000-0000-7000-8000-000000000002',
      principalId: '018f0000-0000-7000-8000-000000000003',
      participantEpoch: '4',
      principalEpoch: '5',
      assignmentId: '018f0000-0000-7000-8000-000000000006',
      assignmentRowVersion: '7',
      authorityEnvelopeId: '018f0000-0000-7000-8000-000000000008',
      authorityEpoch: '9',
      delegationEpoch: '10',
    });
    expect(Object.keys(response)).toEqual([
      'sessionId',
      'sessionEpoch',
      'participantId',
      'principalId',
      'participantEpoch',
      'principalEpoch',
      'assignmentId',
      'assignmentRowVersion',
      'authorityEnvelopeId',
      'authorityEpoch',
      'delegationEpoch',
    ]);
  });

  it('admits only a bearer-authenticated claim for the configured browser origin', () => {
    const token = 'a'.repeat(32);
    const resolve = localWebAuthnAllowedOrigin(
      token,
      'http://localhost:8080/api/v1/ui/oidc-session/callback',
    );
    expect(resolve({ host: 'envoy:8080', origin: 'http://envoy:8080' })).toBeUndefined();
    expect(
      resolve({
        'authorization': `Bearer ${token}`,
        'x-openpc-browser-origin': 'http://localhost:8080',
      }),
    ).toBe('http://localhost:8080');
    expect(
      resolve({
        'authorization': `Bearer ${token}`,
        'x-openpc-browser-origin': 'http://attacker.example',
      }),
    ).toBeNull();
    expect(
      resolve({
        'authorization': `Bearer ${'b'.repeat(32)}`,
        'x-openpc-browser-origin': 'http://localhost:8080',
      }),
    ).toBeNull();
  });

  it('accepts the exact local-only configuration and rejects unknown identity inputs', async () => {
    const { environment } = await fixture();
    await expect(readLocalIdentityRuntimeConfig(environment)).resolves.toMatchObject({
      internalToken: 'a'.repeat(32),
      OPENPC_LOCAL_RUNTIME_QA_FIXTURE: '0',
    });
    await expect(
      readLocalIdentityRuntimeConfig({
        ...environment,
        OPENPC_LOCAL_RUNTIME_QA_FIXTURE: '1',
        IDENTITY_LOCAL_QA_RUNTIME_SNAPSHOT_TTL_MS: '3600000',
      }),
    ).resolves.toMatchObject({ IDENTITY_LOCAL_QA_RUNTIME_SNAPSHOT_TTL_MS: 3_600_000 });
    await expect(
      readLocalIdentityRuntimeConfig({
        ...environment,
        IDENTITY_LOCAL_QA_RUNTIME_SNAPSHOT_TTL_MS: '3600000',
      }),
    ).rejects.toThrow('Runtime snapshot lifetime requires local QA fixture');
    await expect(
      readLocalIdentityRuntimeConfig({
        ...environment,
        OPENPC_LOCAL_RUNTIME_QA_FIXTURE: '1',
        IDENTITY_LOCAL_QA_RUNTIME_SNAPSHOT_TTL_MS: '3600001',
      }),
    ).rejects.toThrow();
    await expect(
      readLocalIdentityRuntimeConfig({
        ...environment,
        IDENTITY_LOCAL_QA_SESSION_TIMEOUT_MS: '86400000',
      }),
    ).resolves.toMatchObject({ IDENTITY_LOCAL_QA_SESSION_TIMEOUT_MS: 86_400_000 });
    await expect(
      readLocalIdentityRuntimeConfig({
        ...environment,
        IDENTITY_LOCAL_QA_SESSION_TIMEOUT_MS: '3600000',
      }),
    ).rejects.toThrow('Invalid local QA session timeout');
    await expect(
      readLocalIdentityRuntimeConfig({ ...environment, IDENTITY_UNKNOWN: 'forbidden' }),
    ).rejects.toThrow('unknown local identity variable');
    await expect(
      readLocalIdentityRuntimeConfig({ ...environment, OPENPC_LOCAL_RUNTIME: '0' }),
    ).rejects.toThrow();
    await expect(
      readLocalIdentityRuntimeConfig({ ...environment, IDENTITY_DATABASE_PORT: '0' }),
    ).rejects.toThrow();
    await expect(
      readLocalIdentityRuntimeConfig({ ...environment, IDENTITY_LISTEN: '0.0.0.0:99999' }),
    ).rejects.toThrow();
    await expect(
      readLocalIdentityRuntimeConfig({ ...environment, IDENTITY_INTERNAL_TOKEN_FILE: '/missing' }),
    ).rejects.toThrow();
  });

  it('bootstraps independent ES256 continuation trust alongside Ed25519 runtime trust', async () => {
    const { paths, environment } = await fixture();
    const pair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const privatePath = paths.runtimePrivateKey + '-continuation';
    const publicPath = paths.runtimePublicKey + '-continuation';
    await writeFile(privatePath, pair.privateKey.export({ format: 'der', type: 'pkcs8' }));
    await writeFile(publicPath, pair.publicKey.export({ format: 'der', type: 'spki' }));
    const complete = {
      ...environment,
      IDENTITY_SIGNING_CONTINUATION_CLIENT_CA_FILE: paths.ca,
      IDENTITY_SIGNING_CONTINUATION_LISTEN: '0.0.0.0:3444',
      IDENTITY_SIGNING_CONTINUATION_PRIVATE_KEY_FILE: privatePath,
      IDENTITY_SIGNING_CONTINUATION_PUBLIC_KEY_FILE: publicPath,
      IDENTITY_SIGNING_CONTINUATION_TRUSTED_PUBLIC_KEY_FILES: publicPath,
    };
    const config = await readLocalIdentityRuntimeConfig(complete);
    const crypto = await readLocalSigningContinuationCrypto(config);
    expect(typeof crypto?.sign).toBe('function');
    expect(typeof crypto?.verify).toBe('function');
    await expect(
      readLocalSigningContinuationCrypto({
        ...config,
        IDENTITY_SIGNING_CONTINUATION_PUBLIC_KEY_FILE: paths.runtimePublicKey,
      }),
    ).rejects.toThrow('Signing continuation is unavailable');
    for (const key of Object.keys(complete).filter((key) =>
      key.startsWith('IDENTITY_SIGNING_CONTINUATION_'),
    )) {
      await expect(
        readLocalIdentityRuntimeConfig({ ...complete, [key]: undefined }),
      ).rejects.toThrow('Incomplete');
    }
    await expect(
      readLocalSigningContinuationCrypto(await readLocalIdentityRuntimeConfig(environment)),
    ).resolves.toBeUndefined();
  });

  it('denies wrong credentials without database access and reports unavailable readiness', async () => {
    const { environment } = await fixture();
    const config = await readLocalIdentityRuntimeConfig(environment);
    const { app, pool } = await buildLocalIdentityRuntime(config);
    const denied = await app.inject({
      method: 'POST',
      url: '/internal/v1/local/session/login',
      headers: { authorization: `Bearer ${'a'.repeat(32)}` },
      payload: { role: 'operator', credential: 'wrong' },
    });
    expect(denied.statusCode).toBe(401);
    expect(denied.json()).toEqual({ code: 'PC-AUTH-0005' });
    const wrongBearer = await app.inject({
      method: 'POST',
      url: '/internal/v1/local/session/login',
      headers: { authorization: `Bearer ${'b'.repeat(32)}` },
      payload: { role: 'operator', credential: 'a'.repeat(32) },
    });
    expect(wrongBearer.statusCode).toBe(403);
    const removedCallerFactsEndpoint = await app.inject({
      method: 'POST',
      url: '/internal/v1/local/workload/authenticate',
    });
    expect(removedCallerFactsEndpoint.statusCode).toBe(404);
    const readiness = await app.inject({ method: 'GET', url: '/readyz' });
    expect(readiness.statusCode).toBe(503);
    await app.close();
    await pool.end();
  });
});

it('optional observer input failure remains separate from Identity configuration', async () => {
  const f = await fixture();
  for (const value of ['', '/unavailable/optional-observer']) {
    const config = await readLocalIdentityRuntimeConfig({
      ...f.environment,
      IDENTITY_QUALIFICATION_OBSERVER_FILE: value,
    });
    expect(config.IDENTITY_QUALIFICATION_OBSERVER_FILE).toBe(value);
  }
});

it('validates recovery lifetimes before loading runtime secrets', async () => {
  const { environment } = await fixture();
  await expect(
    readLocalIdentityRuntimeConfig({ ...environment, IDENTITY_RECOVERY_LEASE_TTL_MS: '3600000' }),
  ).rejects.toThrow('local QA');
  const qa = await readLocalIdentityRuntimeConfig({
    ...environment,
    OPENPC_LOCAL_RUNTIME_QA_FIXTURE: '1',
    IDENTITY_RECOVERY_LEASE_TTL_MS: '3600000',
    IDENTITY_RECOVERY_ADMINISTRATOR_TTL_MS: '28800000',
  });
  expect(qa.IDENTITY_RECOVERY_LEASE_TTL_MS).toBe(3600000);
  await expect(
    readLocalIdentityRuntimeConfig({
      ...environment,
      OPENPC_LOCAL_RUNTIME_QA_FIXTURE: '1',
      IDENTITY_RECOVERY_LEASE_TTL_MS: '3600001',
    }),
  ).rejects.toThrow();
});

it.each([
  [new IdentityKernelError('PC-AUTH-0003'), 401, 'PC-AUTH-0005'],
  [new Error('private database failure'), 503, 'PC-INTEGRATION-5001'],
  [new IdentityKernelError('PC-IDENTITY-1004'), 503, 'PC-INTEGRATION-5001'],
  [
    Object.assign(new Error('private failure'), { code: 'PC-AUTH-0003' }),
    503,
    'PC-INTEGRATION-5001',
  ],
] as const)(
  'distinguishes authoritative session denial from failed session reads (%s)',
  async (error, status, code) => {
    const { environment } = await fixture();
    const config = await readLocalIdentityRuntimeConfig(environment);
    const runtime = await buildLocalIdentityRuntime(config);
    const snapshot = vi.spyOn(runtime.kernel, 'sessionSnapshot').mockRejectedValue(error);
    try {
      const response = await runtime.app.inject({
        method: 'POST',
        url: '/internal/v1/local/session/validate',
        headers: { authorization: `Bearer ${config.internalToken}` },
        payload: { sessionToken: 'original-private-token' },
      });
      expect(response.statusCode).toBe(status);
      expect(response.json()).toEqual({ code });
      expect(response.body).not.toContain('private');
    } finally {
      snapshot.mockRestore();
      await runtime.app.close();
      await runtime.pool.end();
    }
  },
);

it.each([
  [new Error('private authority service failure'), 503],
  [new IdentityKernelError('PC-IDENTITY-1002'), 200],
  [new IdentityKernelError('PC-IDENTITY-1004'), 503],
] as const)(
  'distinguishes optional Platform eligibility denial from unavailability (%s)',
  async (error, status) => {
    const { environment } = await fixture();
    const config = await readLocalIdentityRuntimeConfig(environment);
    const runtime = await buildLocalIdentityRuntime(config);
    const participantId = environment.IDENTITY_LOCAL_PARTICIPANT_ID;
    const now = new Date();
    const snapshot = vi.spyOn(runtime.kernel, 'sessionSnapshot').mockResolvedValue({
      sessionId: '018f0000-0000-7000-8000-000000000701',
      sessionToken: 'original-private-token',
      principalId: environment.IDENTITY_LOCAL_OPERATOR_PRINCIPAL_ID,
      participantId,
      contextMode: 'PLATFORM',
      contextEpoch: '1',
      participantEpoch: '1',
      authorityEpoch: '1',
      sessionEpoch: '1',
      refreshFamilyId: '018f0000-0000-7000-8000-000000000702',
      state: 'ACTIVE',
      issuedAt: now,
      lastSeenAt: now,
      idleExpiresAt: new Date(now.getTime() + 60000),
      absoluteExpiresAt: new Date(now.getTime() + 60000),
    });
    const privacy = vi
      .spyOn(sessionContext, 'sessionPrivacyContext')
      .mockResolvedValue(environment.IDENTITY_LOCAL_PRIVACY_DOMAIN_ID);
    const contexts = vi
      .spyOn(sessionContext, 'availableSessionPrivacyContexts')
      .mockResolvedValue([]);
    const authority = vi
      .spyOn(policyAuthorization, 'authorizeLocalPolicyAction')
      .mockRejectedValue(error);
    try {
      const response = await runtime.app.inject({
        method: 'POST',
        url: '/internal/v1/local/session/validate',
        headers: { authorization: `Bearer ${config.internalToken}` },
        payload: { sessionToken: 'original-private-token' },
      });
      expect(authority).toHaveBeenCalledOnce();
      expect(response.statusCode).toBe(status);
      if (status === 200) {
        expect(response.json()).toMatchObject({
          contextMode: 'PLATFORM',
          platformBootstrapEligible: false,
          availableContexts: [],
        });
        expect(contexts).toHaveBeenCalledOnce();
      } else {
        expect(response.json()).toEqual({ code: 'PC-INTEGRATION-5001' });
        expect(contexts).not.toHaveBeenCalled();
      }
    } finally {
      snapshot.mockRestore();
      privacy.mockRestore();
      contexts.mockRestore();
      authority.mockRestore();
      await runtime.app.close();
      await runtime.pool.end();
    }
  },
);
