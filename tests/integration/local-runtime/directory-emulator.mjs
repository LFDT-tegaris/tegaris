import { readFileSync } from 'node:fs';
import { createServer, get } from 'node:https';
import { X509Certificate } from 'node:crypto';
const ca = readFileSync('/run/secrets/directory_ca'),
  client = readFileSync('/run/secrets/directory_client_cert');
if (process.argv[2] === 'health') {
  get(
    'https://directory-emulator:3447/healthz',
    {
      ca,
      cert: client,
      key: readFileSync('/run/secrets/directory_client_key'),
      minVersion: 'TLSv1.3',
      maxVersion: 'TLSv1.3',
    },
    (response) => {
      response.resume();
      process.exitCode = response.statusCode === 200 ? 0 : 1;
    },
  ).on('error', () => {
    process.exitCode = 1;
  });
} else {
  const expectedPeer = new X509Certificate(client).raw;
  createServer(
    {
      cert: readFileSync('/run/secrets/directory_server_cert'),
      key: readFileSync('/run/secrets/directory_server_key'),
      ca,
      requestCert: true,
      rejectUnauthorized: true,
      minVersion: 'TLSv1.3',
      maxVersion: 'TLSv1.3',
    },
    (request, response) => {
      const send = (status, body) => {
        response.writeHead(status, {
          'content-type': 'application/scim+json',
          'cache-control': 'no-store',
        });
        response.end(JSON.stringify(body));
      };
      if (
        !request.socket.authorized ||
        !request.socket.getPeerCertificate().raw.equals(expectedPeer)
      )
        return send(403, {});
      const url = new URL(request.url, 'https://directory-emulator:3447');
      if (url.pathname === '/healthz') return send(200, { status: 'ok' });
      const state = JSON.parse(readFileSync('/directory/state.json', 'utf8'));
      if (state.status !== 200) return send(state.status, {});
      if (request.method === 'GET' && url.pathname.startsWith('/scim/v2/Groups/')) {
        const group = state.groups?.find(
          (group) => group.id === decodeURIComponent(url.pathname.slice('/scim/v2/Groups/'.length)),
        );
        if (!group) return send(404, {});
        response.setHeader('etag', group.meta.version);
        return send(200, group);
      }
      if (request.method !== 'GET' || url.pathname !== '/scim/v2/Users') return send(404, {});
      const start = Number(url.searchParams.get('startIndex')),
        count = Number(url.searchParams.get('count'));
      const resources = state.users.slice(start - 1, start - 1 + count);
      return send(200, {
        schemas: ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
        totalResults: state.users.length,
        startIndex: start,
        itemsPerPage: resources.length,
        Resources: resources,
      });
    },
  ).listen(3447, '0.0.0.0');
}
