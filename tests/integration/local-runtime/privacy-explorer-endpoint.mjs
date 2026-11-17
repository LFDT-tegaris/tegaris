// External-only fixture. Runs inside the owned Control container's network
// namespace so the real adapter retains its exact loopback TLS restriction.
import assert from 'node:assert/strict';
import { createHash, X509Certificate } from 'node:crypto';
import { appendFile, readFile, writeFile } from 'node:fs/promises';
import { createServer } from 'node:https';
import { join } from 'node:path';
import { setTimeout } from 'node:timers/promises';

const root = process.argv[2];
assert.ok(root);
const canonical = (value) => {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object')
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`)
      .join(',')}}`;
  return JSON.stringify(value);
};
const digest = (value) => `sha256:${createHash('sha256').update(canonical(value)).digest('hex')}`;
const [ca, cert, key, clientPem, profileBytes] = await Promise.all(
  ['ca.crt', 'server.crt', 'server.key', 'client.crt', 'profile.json'].map((name) =>
    readFile(join(root, name)),
  ),
);
const expectedClient = new X509Certificate(clientPem).raw;
const profile = JSON.parse(profileBytes);
const state = '/tmp/openpc-explorer-endpoint';
const exactPeer = (socket) =>
  socket.authorized &&
  socket.getProtocol() === 'TLSv1.3' &&
  socket.getPeerCertificate().raw?.equals(expectedClient);
let calls = 0;
const server = createServer(
  {
    ca,
    cert,
    key,
    requestCert: true,
    rejectUnauthorized: true,
    minVersion: 'TLSv1.3',
    maxVersion: 'TLSv1.3',
  },
  async (req, res) => {
    try {
      assert.ok(exactPeer(req.socket));
      assert.equal(req.method, 'POST');
      assert.equal(req.url, '/v1/privacy-explorer/projection:read');
      assert.equal(req.headers['content-type'], 'application/json');
      assert.equal(req.headers.accept, 'application/json');
      assert.equal(req.headers.cookie, undefined);
      assert.equal(req.headers.authorization, undefined);
      const chunks = [];
      let size = 0;
      for await (const chunk of req) {
        size += chunk.length;
        assert.ok(size <= 1_048_576);
        chunks.push(chunk);
      }
      const { request, context } = JSON.parse(Buffer.concat(chunks));
      assert.deepEqual(request.exportProfile, profile);
      assert.equal(context.profileDigest, profile.digest);
      assert.ok(Date.parse(context.deadlineAt) > Date.parse(request.issuedAt));
      assert.equal(request.scope.platformId, profile.sourceBinding.platformId);
      assert.equal(request.scope.workloadId, profile.sourceBinding.workloadId);
      assert.equal(request.purpose, 'AUDIT');
      assert.equal(request.dataClassId, 'CLASS-READ');
      assert.ok(request.projectionFields.every((field) => profile.allowedFieldIds.includes(field)));
      assert.ok(request.page.limit >= 1 && request.page.limit <= profile.maximumPageSize);
      assert.ok(
        request.page.cursor === null ||
          request.page.cursor === undefined ||
          request.page.cursor === 'external-next-page',
      );
      const mode = (await readFile(join(root, 'mode'), 'utf8')).trim();
      calls += 1;
      await appendFile(
        `${state}.calls`,
        `${JSON.stringify({ call: calls, requestDigest: digest(request), mode, tls: req.socket.getProtocol() })}\n`,
      );
      if (mode === 'PAUSE') {
        const until = Date.parse(context.deadlineAt);
        while (
          !res.destroyed &&
          Date.now() < until &&
          (await readFile(join(root, 'mode'), 'utf8')).trim() === 'PAUSE'
        )
          await setTimeout(25);
        if (res.destroyed) return;
      }
      const unknown = mode === 'UNKNOWN';
      const partial = mode === 'PARTIAL' && !request.page.cursor;
      const values = { 'PEF-A': 'explorer-visible-canary', 'PEF-B': 7 };
      const records =
        mode === 'EMPTY' || unknown
          ? []
          : [
              {
                id: request.page.cursor ? 'external-record-b' : 'external-record-a',
                fields: request.projectionFields.map((fieldId) => ({
                  fieldId,
                  value: values[fieldId],
                })),
              },
            ];
      const requestDigest = digest(request);
      const response = {
        schemaVersion: '1.0',
        requestDigest,
        profileDigest: profile.digest,
        provenanceDigest: digest({
          profileDigest: profile.digest,
          requestDigest,
          provenanceProfileDigest: profile.provenanceProfileDigest,
        }),
        observedAt: request.issuedAt,
        records,
        page: { cursor: partial ? 'external-next-page' : null, gapFree: !partial && !unknown },
        completeness: unknown ? 'UNKNOWN' : partial ? 'PARTIAL' : 'COMPLETE',
        freshness: unknown ? 'UNKNOWN' : 'FRESH',
        conflict: mode === 'REORG' ? 'REORG' : 'NONE',
      };
      const body = {
        ...response,
        responseDigest: mode === 'WRONG_DIGEST' ? `sha256:${'0'.repeat(64)}` : digest(response),
      };
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(
        mode === 'MALFORMED'
          ? '{'
          : mode === 'OVERSIZED'
            ? ' '.repeat(2_097_152)
            : JSON.stringify(body),
      );
    } catch {
      if (!res.headersSent) res.writeHead(400, { 'content-type': 'application/json' });
      res.end('{}');
    }
  },
);
server.on('secureConnection', (socket) => {
  if (!exactPeer(socket)) socket.destroy();
});
server.listen(55443, '127.0.0.1', async () => {
  await writeFile(`${state}.ready`, String(process.pid));
});
for (const signal of ['SIGTERM', 'SIGINT'])
  process.once(signal, () => {
    server.closeAllConnections();
    server.close(() => process.exit(0));
  });
