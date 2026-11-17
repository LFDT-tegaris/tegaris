import { createServer, type Server } from 'node:https';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { TLSSocket } from 'node:tls';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { runtimeSnapshotTlsFixture } from '../../../../tests/integration/identity/runtime-snapshot-tls-fixture.js';
import { createHttpScimDirectorySource } from './http-scim-directory-source.js';
import { createRegisteredDirectoryProfiles } from './directory-profiles.js';
import {
  ScimDirectoryUnavailable,
  scimGroupSchemaUrn,
  scimListSchemaUrn,
  scimUserSchemaUrn,
  type ScimDirectorySource,
} from './scim-directory-source.js';

const profileId = '01990000-0000-7000-8000-000000000113';
const user = (id = 'provider/user-A') => ({
  schemas: [scimUserSchemaUrn],
  id,
  userName: 'directory-display-only',
  active: true,
  meta: { resourceType: 'User', version: 'W/"opaque-7"', lastModified: '2026-09-15T00:00:00Z' },
});
function page(resources: unknown[], totalResults = resources.length, startIndex = 1) {
  return {
    schemas: [scimListSchemaUrn],
    totalResults,
    startIndex,
    itemsPerPage: resources.length,
    Resources: resources,
  };
}
const send = (response: ServerResponse, body: unknown, status = 200) => {
  response.writeHead(status, { 'content-type': 'application/scim+json', 'etag': 'W/"opaque-7"' });
  response.end(JSON.stringify(body));
};

describe('registered SCIM reader over real mutually authenticated TLS', () => {
  let tls: Awaited<ReturnType<typeof runtimeSnapshotTlsFixture>>;
  let server: Server;
  let baseUrl: string;
  let source: ScimDirectorySource;
  let handler: (request: IncomingMessage, response: ServerResponse) => void;
  beforeAll(async () => {
    tls = await runtimeSnapshotTlsFixture(`urn:openpc:directory-profile:${profileId}`);
    server = createServer(
      {
        cert: tls.server.certificate,
        key: tls.server.privateKey,
        ca: tls.server.ca,
        requestCert: true,
        rejectUnauthorized: true,
        minVersion: 'TLSv1.3',
        maxVersion: 'TLSv1.3',
      },
      (request, response) => {
        const peer = request.socket as TLSSocket;
        if (
          !peer.authorized ||
          peer.getProtocol() !== 'TLSv1.3' ||
          !peer.getPeerCertificate().raw.equals(tls.parsed.raw)
        ) {
          send(response, {}, 403);
          return;
        }
        handler(request, response);
      },
    );
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('Missing SCIM fixture address');
    baseUrl = `https://127.0.0.1:${address.port}/scim/v2`;
    source = createHttpScimDirectorySource({
      profileId,
      baseUrl,
      certificate: tls.certificate,
      privateKey: tls.privateKey,
      trustCa: tls.server.ca,
    });
  });
  afterAll(async () => {
    source?.close();
    server?.closeAllConnections();
    if (server) await new Promise<void>((resolve) => server.close(() => resolve()));
    await tls?.close();
  });
  it('preserves exact provider IDs and opaque versions, strips unrelated data and never infers deletions', async () => {
    const requests: string[] = [];
    handler = (request, response) => {
      expect(request.method).toBe('GET');
      requests.push(request.url!);
      const start = new URL(request.url!, baseUrl).searchParams.get('startIndex');
      send(
        response,
        page(
          [
            {
              ...user(start === '1' ? 'A' : 'a'),
              password: 'must-not-retain',
              emails: ['private@example.invalid'],
              roles: ['admin'],
              externalId: 'not-an-identity',
            },
          ],
          2,
          Number(start),
        ),
      );
    };
    const result = await source.enumerate('Users');
    expect(result.resources.map((item) => item.id)).toEqual(['A', 'a']);
    expect(result.resources[0]?.version).toBe('W/"opaque-7"');
    expect(result.omissionMeaning).toBe('NONE');
    expect(JSON.stringify(result)).not.toMatch(/must-not-retain|private@|not-an-identity|admin/);
    expect(requests).toEqual([
      '/scim/v2/Users?startIndex=1&count=100',
      '/scim/v2/Users?startIndex=2&count=100',
    ]);
    handler = (_request, response) =>
      send(response, { schemas: [scimListSchemaUrn], totalResults: 0 });
    expect(await source.enumerate('Users')).toMatchObject({
      resources: [],
      omissionMeaning: 'NONE',
    });
  });
  it('binds a direct read to its exact ID and matching HTTP/resource version', async () => {
    let path = '';
    handler = (request, response) => {
      path = request.url!;
      send(response, user());
    };
    expect(await source.read('Users', 'provider/user-A')).toMatchObject({
      id: 'provider/user-A',
      active: true,
    });
    expect(path).toBe('/scim/v2/Users/provider%2Fuser-A');
    await expect(source.read('Users', 'other')).rejects.toBeInstanceOf(ScimDirectoryUnavailable);
    handler = (_request, response) =>
      send(response, { ...user(), meta: { ...user().meta, version: 'W/"changed"' } });
    await expect(source.read('Users', 'provider/user-A')).rejects.toBeInstanceOf(
      ScimDirectoryUnavailable,
    );
  });
  it('resolves exact registered references into the real mTLS reader', async () => {
    handler = (_request, response) => send(response, page([user()]));
    const resolved: string[] = [];
    const registry = await createRegisteredDirectoryProfiles(
      [
        {
          participantId: profileId,
          profileId,
          baseUrl,
          oidcIssuer: 'https://idp.example.invalid',
          oidcClientId: 'openpc',
          subjectMapping: 'SCIM_ID',
          certificateRef: 'secret://local/client#1',
          privateKeyRef: 'secret://local/key#1',
          trustCaRef: 'secret://local/ca#1',
        },
      ],
      async (reference) => {
        resolved.push(reference);
        if (reference === 'secret://local/client#1') return tls.certificate;
        if (reference === 'secret://local/key#1') return tls.privateKey;
        if (reference === 'secret://local/ca#1') return tls.server.ca;
        throw new Error('Unknown fixture reference');
      },
    );
    try {
      expect(
        (await registry.get(profileId, profileId).source.enumerate('Users')).resources[0]?.id,
      ).toBe('provider/user-A');
      expect(resolved).toEqual([
        'secret://local/client#1',
        'secret://local/key#1',
        'secret://local/ca#1',
      ]);
    } finally {
      registry.close();
    }
  });
  it('retains unresolved group types without manufacturing human membership', async () => {
    handler = (_request, response) =>
      send(
        response,
        page([
          {
            schemas: [scimGroupSchemaUrn],
            id: 'G',
            displayName: 'External group',
            meta: { ...user().meta, resourceType: 'Group' },
            members: [
              { value: 'human', type: 'User' },
              { value: 'nested', type: 'Group' },
              { value: 'unknown' },
            ],
          },
        ]),
      );
    expect((await source.enumerate('Groups')).resources[0]).toMatchObject({
      members: [
        { id: 'human', type: 'User' },
        { id: 'nested', type: 'Group' },
        { id: 'unknown', type: null },
      ],
    });
    handler = (_request, response) =>
      send(
        response,
        page([
          {
            schemas: [scimGroupSchemaUrn],
            id: 'G',
            displayName: 'Unknown members',
            meta: { ...user().meta, resourceType: 'Group' },
          },
        ]),
      );
    expect((await source.enumerate('Groups')).resources[0]).toMatchObject({ members: null });
    handler = (_request, response) =>
      send(
        response,
        page([
          {
            schemas: [scimGroupSchemaUrn],
            id: 'G',
            displayName: 'Empty group',
            meta: { ...user().meta, resourceType: 'Group' },
            members: [],
          },
        ]),
      );
    expect((await source.enumerate('Groups')).resources[0]).toMatchObject({ members: [] });
  });
  it.each([401, 403, 404, 429, 500, 503])(
    'returns the registered failure for HTTP %s without retry or deletion evidence',
    async (status) => {
      let calls = 0;
      handler = (_request, response) => {
        calls++;
        send(response, { detail: 'provider-secret-body' }, status);
      };
      await expect(source.read('Users', 'known')).rejects.toMatchObject({
        message: 'PC-AUTH-0002',
        code: 'PC-AUTH-0002',
      });
      expect(calls).toBe(1);
    },
  );
  it('does not redirect a registered client to a provider-controlled location', async () => {
    let calls = 0;
    handler = (_request, response) => {
      calls++;
      response.writeHead(302, { location: '/different-tenant/Users' });
      response.end();
    };
    await expect(source.enumerate('Users')).rejects.toBeInstanceOf(ScimDirectoryUnavailable);
    expect(calls).toBe(1);
  });
  it.each([
    'duplicate',
    'total-drift',
    'empty-page',
    'wrong-index',
    'wrong-count',
    'overflow',
    'missing-active',
    'missing-version',
  ])('rejects an incomplete or inconsistent enumeration: %s', async (failure) => {
    handler = (request, response) => {
      const start = Number(new URL(request.url!, baseUrl).searchParams.get('startIndex'));
      if (start === 1 && ['duplicate', 'total-drift'].includes(failure))
        return send(response, page([user('one')], 2));
      const value = user('one');
      const body =
        failure === 'missing-active'
          ? { ...value, active: undefined }
          : failure === 'missing-version'
            ? { ...value, meta: { ...value.meta, version: undefined } }
            : value;
      send(response, {
        ...page(
          failure === 'empty-page' ? [] : [body],
          failure === 'overflow'
            ? 5001
            : failure === 'total-drift'
              ? 3
              : failure === 'duplicate'
                ? 2
                : 1,
          failure === 'wrong-index' ? 2 : start,
        ),
        ...(failure === 'wrong-count' ? { itemsPerPage: 2 } : {}),
      });
    };
    await expect(source.enumerate('Users')).rejects.toBeInstanceOf(ScimDirectoryUnavailable);
  });
  it('bounds oversized and invalid UTF-8 responses', async () => {
    handler = (_request, response) => send(response, { padding: 'x'.repeat(1_048_577) });
    await expect(source.enumerate('Users')).rejects.toBeInstanceOf(ScimDirectoryUnavailable);
    handler = (_request, response) => {
      response.writeHead(200, { 'content-type': 'application/scim+json' });
      response.end(Buffer.from([0x7b, 0x22, 0xc3, 0x28, 0x22, 0x7d]));
    };
    await expect(source.enumerate('Users')).rejects.toBeInstanceOf(ScimDirectoryUnavailable);
  });
  it('bounds a trickling peer and rejects concurrent observations rather than creating a queue', async () => {
    const short = createHttpScimDirectorySource({
      profileId,
      baseUrl,
      certificate: tls.certificate,
      privateKey: tls.privateKey,
      trustCa: tls.server.ca,
      timeoutMs: 100,
    });
    let interval: ReturnType<typeof setInterval> | undefined;
    handler = (_request, response) => {
      response.writeHead(200, { 'content-type': 'application/scim+json' });
      response.write('{');
      interval = setInterval(() => response.write(' '), 10);
      response.once('close', () => clearInterval(interval));
    };
    try {
      const first = short.enumerate('Users');
      await expect(short.enumerate('Users')).rejects.toBeInstanceOf(ScimDirectoryUnavailable);
      await expect(first).rejects.toBeInstanceOf(ScimDirectoryUnavailable);
    } finally {
      clearInterval(interval);
      short.close();
    }
  });
  it('rejects a certificate from another trust domain and untrusted server certificates', async () => {
    const other = await runtimeSnapshotTlsFixture('urn:openpc:directory-profile:unregistered');
    let calls = 0;
    handler = (_request, response) => {
      calls++;
      send(response, page([]));
    };
    const unauthorized = createHttpScimDirectorySource({
      profileId,
      baseUrl,
      certificate: other.certificate,
      privateKey: other.privateKey,
      trustCa: tls.server.ca,
    });
    const untrusted = createHttpScimDirectorySource({
      profileId,
      baseUrl,
      certificate: tls.certificate,
      privateKey: tls.privateKey,
      trustCa: other.server.ca,
    });
    try {
      await expect(unauthorized.enumerate('Users')).rejects.toBeInstanceOf(
        ScimDirectoryUnavailable,
      );
      await expect(untrusted.enumerate('Users')).rejects.toBeInstanceOf(ScimDirectoryUnavailable);
      expect(calls).toBe(0);
    } finally {
      unauthorized.close();
      untrusted.close();
      await other.close();
    }
  });
});
