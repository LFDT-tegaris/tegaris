import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import Fastify from 'fastify';
import { Pool } from 'pg';
import { expect, it, vi } from 'vitest';
import {
  createGate3ConformantEndpoint,
  gate3EndpointPaths,
} from '../../../../tests/privacy/i07-gate3-conformant-endpoint.js';
import { createLocalConfigurationAuthorizer } from '../configuration/local-authorizer.js';
import { loadExplorerTransport, registerLivePrivacyExplorer } from './live-runtime.js';

it('starts the real public route with operator TLS material read from files', async () => {
  const scratch = process.env.OPENPC_TEST_TMP_ROOT;
  if (!scratch) throw new Error('Owned test scratch required');
  const root = await mkdtemp(join(scratch, 'explorer-startup-'));
  vi.stubEnv('OPENPC_PNC_TMP_ROOT', root);
  const endpoint = await createGate3ConformantEndpoint(
    Object.values(gate3EndpointPaths).map((path) => ({
      path,
      expectedBody: Buffer.from('{}'),
      statusCode: 200,
      contentType: 'application/json',
      body: Buffer.from('{}'),
      maximumCalls: 1,
    })),
  );
  const app = Fastify({ logger: false });
  const pool = new Pool({ connectionTimeoutMillis: 1_000 });
  try {
    const keyFile = join(root, 'continuation.key');
    const configFile = join(root, 'transport.json');
    await writeFile(keyFile, 'ab'.repeat(32), { mode: 0o600 });
    await writeFile(
      configFile,
      JSON.stringify({
        origin: endpoint.origin,
        productId: 'External test fixture',
        instanceId: 'startup',
        releaseVersion: '1.0.0',
        buildDigest: `sha256:${'a'.repeat(64)}`,
        adapterVersion: '1.0.0',
        transportProfileId: 'local-transport@v1',
        egressPolicyId: 'local-egress@v1',
        trustAnchorId: 'local-ca@v1',
        clientIdentityId: 'local-client@v1',
        trustAnchorFile: join(endpoint.privateMaterialRoot, 'ca.crt'),
        clientCertificateFile: join(endpoint.privateMaterialRoot, 'client.crt'),
        clientPrivateKeyFile: join(endpoint.privateMaterialRoot, 'client.key'),
        continuationKeyFile: keyFile,
        requestByteLimit: 65_536,
        responseByteLimit: 1_048_576,
        maximumJsonDepth: 32,
      }),
      { mode: 0o600 },
    );
    const transport = await loadExplorerTransport(configFile);
    const identityUrl = 'http://127.0.0.1:53001';
    await registerLivePrivacyExplorer(app, {
      pool,
      transport,
      identityUrl,
      authorizer: createLocalConfigurationAuthorizer(
        identityUrl,
        'unused-startup-test-token',
        '018f0000-0000-7000-8000-000000000201',
      ),
    });
    await app.ready();
    const denied = await app.inject({
      method: 'GET',
      url: '/v1/privacy-explorer/occurrences/018f0000-0000-7000-8000-000000000301',
    });
    expect(denied.statusCode).toBe(403);
    expect(denied.headers['cache-control']).toBe('no-store');
    expect(endpoint.calls()).toHaveLength(0);
  } finally {
    await app.close();
    await pool.end();
    await endpoint.close();
    vi.unstubAllEnvs();
    await rm(root, { recursive: true, force: true });
  }
}, 30_000);
