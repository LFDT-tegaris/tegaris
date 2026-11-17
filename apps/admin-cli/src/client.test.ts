import { chmod, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AdministrationClient, apiOrigin, CliError, type CliConfig } from './client.js';
import { run } from './main.js';

const participantId = '018f0000-0000-7000-8000-000000000101';
const privacyDomainId = '018f0000-0000-7000-8000-000000000201';
const sessionToken = `${participantId}.018f0000-0000-7000-8000-000000000301`;
const config: CliConfig = {
  apiUrl: 'https://openpc.example',
  participantId,
  privacyDomainId,
  sessionFile: 'session.json',
  localDevelopment: false,
};
const session = {
  principalId: '018f0000-0000-7000-8000-000000000141',
  participantId,
  privacyDomainId,
  state: 'ACTIVE',
  contextMode: 'PARTICIPANT',
};
const operationId = '018f0000-0000-7000-8000-000000000401';
const operation = {
  operationId,
  resourceRef: `urn:openpc:resource:${operationId}`,
  actionIntentId: 'ACT-CIGL_PROFILES_ACTIVATE_RESOURCE-V1',
  intentDigest: `sha256:${'ab'.repeat(32)}`,
  idempotencyKey: 'cli-read-original-operation-0001',
  state: 'SUCCEEDED',
  truthState: 'SUCCESS',
  revision: '2',
  createdAt: '2026-09-18T06:00:00.000000Z',
  updatedAt: '2026-09-18T06:00:01.000000Z',
};
const json = (value: unknown, status = 200) =>
  new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } });
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('public administration client', () => {
  it('uses authenticated public owners, exact context and no credential redirects', async () => {
    const transport = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(json({ ...session, sessionToken, refreshFamilyId: 'hidden' }))
      .mockResolvedValueOnce(json(operation));
    const client = new AdministrationClient(config, sessionToken, transport);
    expect(await client.read('operation', operationId)).toEqual(operation);
    expect(transport.mock.calls.map(([url]) => url)).toEqual([
      'https://openpc.example/api/v1/session',
      `https://openpc.example/api/v1/operations/${operationId}`,
    ]);
    for (const [, request] of transport.mock.calls) {
      expect(request?.redirect).toBe('error');
      expect(request?.method).toBe('GET');
      const headers = new Headers(request?.headers);
      expect(headers.get('OpenPC-Privacy-Domain-ID')).toBe(
        `urn:openpc:privacy-domain:${privacyDomainId}`,
      );
      expect(headers.get('X-Request-ID')).toMatch(/^[a-f0-9-]{14}7[a-f0-9-]{21}$/u);
    }
    const view = await new AdministrationClient(
      config,
      sessionToken,
      vi
        .fn<typeof fetch>()
        .mockResolvedValue(json({ ...session, sessionToken, refreshFamilyId: 'hidden' })),
    ).session();
    expect(view).toEqual(session);
  });

  it('denies a changed privacy context before reading a resource', async () => {
    const transport = vi
      .fn<typeof fetch>()
      .mockResolvedValue(
        json({ ...session, privacyDomainId: '018f0000-0000-7000-8000-000000000202' }),
      );
    await expect(
      new AdministrationClient(config, sessionToken, transport).read('operation', operationId),
    ).rejects.toMatchObject({ code: 'CONTEXT' });
    expect(transport).toHaveBeenCalledTimes(1);
  });

  it('revalidates authority on every read and preserves public denials', async () => {
    const transport = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(json(session))
      .mockResolvedValueOnce(json(operation))
      .mockResolvedValueOnce(json({ ...session, state: 'REVOKED' }));
    const client = new AdministrationClient(config, sessionToken, transport);
    await client.read('operation', operationId);
    await expect(client.read('operation', operationId)).rejects.toMatchObject({
      code: 'AUTHENTICATION',
    });
    expect(transport).toHaveBeenCalledTimes(3);
  });

  it('rejects unsafe endpoints, path input and credential injection', async () => {
    for (const apiUrl of [
      'http://openpc.example',
      'https://user:secret@openpc.example',
      'https://openpc.example/path',
      'https://openpc.example/?q=secret',
    ])
      expect(() => apiOrigin({ ...config, apiUrl })).toThrow(CliError);
    expect(apiOrigin({ ...config, apiUrl: 'http://127.0.0.1:8080', localDevelopment: true })).toBe(
      'http://127.0.0.1:8080',
    );
    expect(() => new AdministrationClient(config, `${sessionToken}; other=secret`)).toThrow(
      CliError,
    );
    const transport = vi.fn<typeof fetch>();
    await expect(
      new AdministrationClient(config, sessionToken, transport).read('operation', '../session'),
    ).rejects.toMatchObject({ code: 'INPUT' });
    expect(transport).not.toHaveBeenCalled();
  });

  it('never reports transport exceptions, upstream secrets or malformed data', async () => {
    for (const response of [
      json({ secret: sessionToken }),
      json({ detail: sessionToken }, 403),
      json(sessionToken, 404),
    ]) {
      const transport = vi.fn<typeof fetch>().mockResolvedValue(response);
      await expect(
        new AdministrationClient(config, sessionToken, transport).session(),
      ).rejects.toBeInstanceOf(CliError);
    }
    const transport = vi
      .fn<typeof fetch>()
      .mockRejectedValue(new Error(`credential=${sessionToken}`));
    await expect(
      new AdministrationClient(config, sessionToken, transport).session(),
    ).rejects.toMatchObject({ code: 'TRANSPORT', message: 'TRANSPORT' });
  });

  it('bounds response bodies', async () => {
    const transport = vi
      .fn<typeof fetch>()
      .mockResolvedValue(json('x'.repeat(4 * 1024 * 1024 + 1)));
    await expect(
      new AdministrationClient(config, sessionToken, transport).session(),
    ).rejects.toMatchObject({ code: 'RESPONSE' });
  });

  it('requires a protected origin-bound regular session file', async () => {
    const scratch = process.env.OPENPC_TEST_TMP_ROOT;
    if (!scratch) throw new Error('OPENPC_TEST_TMP_ROOT is required');
    const root = await mkdtemp(join(scratch, 'cli-client-'));
    try {
      const cfg = join(root, 'config.json'),
        secret = join(root, 'session.json');
      await writeFile(cfg, JSON.stringify(config));
      await writeFile(secret, JSON.stringify({ origin: 'https://wrong.example', sessionToken }), {
        mode: 0o600,
      });
      await expect(run(['--config', cfg, 'session'], () => undefined)).rejects.toMatchObject({
        code: 'AUTHENTICATION',
      });
      await writeFile(secret, JSON.stringify({ origin: config.apiUrl, sessionToken }));
      await chmod(secret, 0o644);
      await expect(run(['--config', cfg, 'session'], () => undefined)).rejects.toMatchObject({
        code: 'AUTHENTICATION',
      });
      await chmod(secret, 0o600);
      await symlink(secret, join(root, 'linked.json'));
      await writeFile(cfg, JSON.stringify({ ...config, sessionFile: 'linked.json' }));
      await expect(run(['--config', cfg, 'session'], () => undefined)).rejects.toMatchObject({
        code: 'AUTHENTICATION',
      });
      await writeFile(cfg, JSON.stringify(config));
      vi.stubGlobal(
        'fetch',
        vi.fn<typeof fetch>().mockResolvedValue(json({ ...session, sessionToken })),
      );
      const output: unknown[] = [];
      expect(await run(['--config', cfg, 'session'], (value) => output.push(value))).toBe(0);
      expect(output).toEqual([session]);
      const pending = vi
        .fn<typeof fetch>()
        .mockImplementation(async (url) =>
          json(
            String(url).endsWith('/session')
              ? session
              : { ...operation, state: 'ACCEPTED', truthState: 'UNKNOWN' },
          ),
        );
      vi.stubGlobal('fetch', pending);
      const retained: unknown[] = [];
      expect(
        await run(['--config', cfg, 'operation', operationId, '--wait-seconds', '1'], (value) =>
          retained.push(value),
        ),
      ).toBe(6);
      expect(retained).toEqual([{ ...operation, state: 'ACCEPTED', truthState: 'UNKNOWN' }]);
      expect(pending.mock.calls.every(([, init]) => init?.method === 'GET')).toBe(true);
      vi.stubGlobal(
        'fetch',
        vi
          .fn<typeof fetch>()
          .mockImplementation(async (url) =>
            json(String(url).endsWith('/session') ? session : operation),
          ),
      );
      expect(
        await run(
          ['--config', cfg, 'operation', operationId, '--wait-seconds', '1'],
          () => undefined,
        ),
      ).toBe(0);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('rejects a well-formed response for a different operation', async () => {
    const transport = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(json(session))
      .mockResolvedValueOnce(
        json({ ...operation, operationId: '018f0000-0000-7000-8000-000000000402' }),
      );
    await expect(
      new AdministrationClient(config, sessionToken, transport).read('operation', operationId),
    ).rejects.toMatchObject({ code: 'RESPONSE' });
  });
});
