import { createHash, createHmac, randomUUID, timingSafeEqual } from 'node:crypto';
import { createServer } from 'node:http';
import { link, mkdir, open, readdir, readFile, rename, unlink } from 'node:fs/promises';
import { join } from 'node:path';

// Local EXTERNAL-system fixture: the wire surface is the S3 REST subset, with
// independently checked SigV4 and durable objects/protection. No Control,
// authorization, checkpoint, eligibility or key-lifecycle success is simulated.
const namespace = 'http://s3.amazonaws.com/doc/2006-03-01/';
const hex = (bytes) => createHash('sha256').update(bytes).digest('hex');
const escape = (value) =>
  String(value).replace(
    /[&<>"']/gu,
    (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' })[char],
  );
const encode = (value) =>
  encodeURIComponent(value).replace(
    /[!'()*]/gu,
    (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`,
  );
const compare = (left, right) => (left < right ? -1 : left > right ? 1 : 0);

function authenticate(request, bytes, credentials, region, expectedOwner) {
  const match =
    /^AWS4-HMAC-SHA256 Credential=([A-Za-z0-9]+)\/(\d{8})\/([a-z0-9-]+)\/s3\/aws4_request,SignedHeaders=([a-z0-9;-]+),Signature=([0-9a-f]{64})$/u.exec(
      request.headers.authorization ?? '',
    );
  if (
    !match ||
    match[1] !== credentials.accessKeyId ||
    match[3] !== region ||
    request.headers['x-amz-expected-bucket-owner'] !== expectedOwner
  )
    return false;
  if ((request.headers['x-amz-security-token'] ?? undefined) !== credentials.sessionToken)
    return false;
  const names = match[4].split(';');
  if (new Set(names).size !== names.length || [...names].sort(compare).join(';') !== match[4])
    return false;
  const required = ['host', 'x-amz-date', 'x-amz-content-sha256', 'x-amz-expected-bucket-owner'];
  // Every supplied x-amz metadata/protection header must be signed as well.
  required.push(...Object.keys(request.headers).filter((name) => name.startsWith('x-amz-')));
  if (required.some((name) => !names.includes(name))) return false;
  const timestamp = request.headers['x-amz-date'];
  if (
    typeof timestamp !== 'string' ||
    !/^\d{8}T\d{6}Z$/u.test(timestamp) ||
    timestamp.slice(0, 8) !== match[2]
  )
    return false;
  const iso = timestamp.replace(/^(\d{4})(\d\d)(\d\d)T(\d\d)(\d\d)(\d\d)Z$/u, '$1-$2-$3T$4:$5:$6Z');
  if (
    !Number.isFinite(Date.parse(iso)) ||
    Math.abs(Date.now() - Date.parse(iso)) > 300000 ||
    request.headers['x-amz-content-sha256'] !== hex(bytes)
  )
    return false;
  const url = new URL(request.url, 'http://127.0.0.1');
  const canonicalQuery = [...url.searchParams]
    .map(([name, value]) => [encode(name), encode(value)])
    .sort((a, b) => compare(a[0], b[0]) || compare(a[1], b[1]))
    .map((part) => part.join('='))
    .join('&');
  const headerLines = [];
  for (const name of names) {
    const value = request.headers[name];
    if (typeof value !== 'string') return false;
    headerLines.push(`${name}:${value.trim().replace(/\s+/gu, ' ')}\n`);
  }
  const canonical = [
    request.method,
    url.pathname,
    canonicalQuery,
    headerLines.join(''),
    match[4],
    hex(bytes),
  ].join('\n');
  const scope = `${match[2]}/${region}/s3/aws4_request`;
  let key = Buffer.from(`AWS4${credentials.secretAccessKey}`);
  for (const component of [match[2], region, 's3', 'aws4_request']) {
    const next = createHmac('sha256', key).update(component).digest();
    key.fill(0);
    key = next;
  }
  const signature = createHmac('sha256', key)
    .update(`AWS4-HMAC-SHA256\n${timestamp}\n${scope}\n${hex(canonical)}`)
    .digest();
  key.fill(0);
  return timingSafeEqual(signature, Buffer.from(match[5], 'hex'));
}

export async function startRemoteArchiveFixture({
  root,
  bucket,
  expectedOwner,
  region,
  credentials,
  port = 0,
}) {
  await mkdir(root, { recursive: true, mode: 0o700 });
  const syncDirectory = async () => {
    const directory = await open(root, 'r');
    try {
      await directory.sync();
    } finally {
      await directory.close();
    }
  };
  async function persist(name, value, immutable = false) {
    const temporary = join(root, `.pending-${randomUUID()}`);
    const file = await open(temporary, 'wx', 0o600);
    try {
      await file.writeFile(JSON.stringify(value));
      await file.sync();
    } finally {
      await file.close();
    }
    try {
      if (immutable) await link(temporary, join(root, name));
      else await rename(temporary, join(root, name));
      await syncDirectory();
    } finally {
      await unlink(temporary).catch((error) => {
        if (error.code !== 'ENOENT') throw error;
      });
    }
  }
  const objectName = (versionId) => `version-${hex(versionId)}.json`;
  const holdName = (versionId) => `hold-${hex(versionId)}.json`;
  async function objects() {
    const result = [];
    for (const name of await readdir(root)) {
      if (/^version-[0-9a-f]{64}\.json$/u.test(name))
        result.push(JSON.parse(await readFile(join(root, name), 'utf8')));
    }
    return result.sort((a, b) => compare(a.key, b.key) || compare(a.versionId, b.versionId));
  }
  const faults = {
    dropPutResponse: false,
    dropHoldResponse: false,
    denyRead: false,
    corruptRead: false,
    wrongVersion: false,
    shortRetention: false,
    forceHold: null,
    malformedListing: false,
    repeatPage: false,
    pageSize: 100,
    redirectRead: false,
  };
  const counts = { puts: 0, gets: 0, lists: 0, holds: 0, denied: 0 };
  const reads = [];
  const respondXml = (response, rootName, body) => {
    response.writeHead(200, { 'content-type': 'application/xml' });
    response.end(`<${rootName} xmlns="${namespace}">${body}</${rootName}>`);
  };
  const reject = (response, status, code) => {
    response.writeHead(status, { 'content-type': 'application/xml' });
    response.end(`<Error><Code>${code}</Code></Error>`);
  };
  let serial = Promise.resolve();
  const server = createServer((request, response) => {
    const processRequest = async () => {
      const chunks = [];
      let length = 0;
      for await (const chunk of request) {
        length += chunk.length;
        if (length > 2 * 1024 * 1024) {
          reject(response, 413, 'EntityTooLarge');
          return;
        }
        chunks.push(chunk);
      }
      const bytes = Buffer.concat(chunks);
      if (!authenticate(request, bytes, credentials, region, expectedOwner)) {
        counts.denied++;
        reject(response, 403, 'SignatureDoesNotMatch');
        return;
      }
      const url = new URL(request.url, 'http://127.0.0.1');
      const path = decodeURIComponent(url.pathname);
      if (path !== `/${bucket}` && !path.startsWith(`/${bucket}/`)) {
        reject(response, 404, 'NoSuchBucket');
        return;
      }
      const key = path.slice(bucket.length + 2);
      const all = await objects();
      if (request.method === 'GET' && url.searchParams.has('versions')) {
        counts.lists++;
        if (faults.malformedListing) {
          response.end('<ListVersionsResult><IsTruncated>false');
          return;
        }
        const prefix = url.searchParams.get('prefix');
        const matching = all.filter((object) => object.key.startsWith(prefix));
        const marker = url.searchParams.get('version-id-marker');
        const start = marker ? matching.findIndex((object) => object.versionId === marker) + 1 : 0;
        const selected = matching.slice(
          faults.repeatPage ? 0 : start,
          (faults.repeatPage ? 0 : start) + faults.pageSize,
        );
        const truncated = faults.repeatPage || start + selected.length < matching.length;
        let body = `<Name>${escape(bucket)}</Name><Prefix>${escape(encode(prefix))}</Prefix><EncodingType>url</EncodingType><IsTruncated>${truncated}</IsTruncated>`;
        for (const object of selected) {
          const name = object.deleteMarker ? 'DeleteMarker' : 'Version';
          body += `<${name}><Key>${escape(encode(object.key))}</Key><VersionId>${escape(object.versionId)}</VersionId><IsLatest>true</IsLatest></${name}>`;
        }
        if (truncated && selected.length) {
          const last = selected.at(-1);
          body += `<NextKeyMarker>${escape(encode(last.key))}</NextKeyMarker><NextVersionIdMarker>${escape(last.versionId)}</NextVersionIdMarker>`;
        }
        respondXml(response, 'ListVersionsResult', body);
        return;
      }
      if (request.method === 'PUT' && !url.searchParams.has('legal-hold')) {
        counts.puts++;
        if (
          request.headers['if-none-match'] !== '*' ||
          request.headers['x-amz-object-lock-mode'] !== 'COMPLIANCE' ||
          !['ON', 'OFF'].includes(request.headers['x-amz-object-lock-legal-hold']) ||
          createHash('md5').update(bytes).digest('base64') !== request.headers['content-md5']
        ) {
          reject(response, 400, 'InvalidRequest');
          return;
        }
        if (all.some((object) => object.key === key)) {
          reject(response, 412, 'PreconditionFailed');
          return;
        }
        const versionId = `v-${randomUUID()}/+=`;
        const object = {
          key,
          versionId,
          bytes: bytes.toString('base64'),
          retention: request.headers['x-amz-object-lock-retain-until-date'],
          initialHold: request.headers['x-amz-object-lock-legal-hold'],
          metadata: Object.fromEntries(
            Object.entries(request.headers).filter(([name]) => name.startsWith('x-amz-meta-')),
          ),
        };
        await persist(objectName(versionId), object, true);
        if (faults.dropPutResponse) {
          faults.dropPutResponse = false;
          request.socket.destroy();
          return;
        }
        response.writeHead(200, { 'x-amz-version-id': versionId });
        response.end();
        return;
      }
      const object = all.find(
        (entry) => entry.key === key && entry.versionId === url.searchParams.get('versionId'),
      );
      if (!object || object.deleteMarker) {
        reject(response, 404, 'NoSuchVersion');
        return;
      }
      if (request.method === 'GET') {
        counts.gets++;
        reads.push({
          key,
          versionId: object.versionId,
          protection: url.searchParams.has('retention') || url.searchParams.has('legal-hold'),
        });
        if (faults.denyRead) {
          reject(response, 403, 'AccessDenied');
          return;
        }
        if (faults.redirectRead) {
          response.writeHead(307, { location: 'http://127.0.0.1:1/forbidden' });
          response.end();
          return;
        }
        if (url.searchParams.has('retention')) {
          respondXml(
            response,
            'Retention',
            `<Mode>COMPLIANCE</Mode><RetainUntilDate>${escape(faults.shortRetention ? '2000-01-01T00:00:00Z' : object.retention)}</RetainUntilDate>`,
          );
          return;
        }
        if (url.searchParams.has('legal-hold')) {
          let hold = object.initialHold;
          try {
            hold = JSON.parse(await readFile(join(root, holdName(object.versionId)), 'utf8')).hold;
          } catch (error) {
            if (error.code !== 'ENOENT') throw error;
          }
          respondXml(response, 'LegalHold', `<Status>${faults.forceHold ?? hold}</Status>`);
          return;
        }
        const body = Buffer.from(object.bytes, 'base64');
        if (faults.corruptRead) body[0] ^= 1;
        response.writeHead(200, {
          ...object.metadata,
          'x-amz-version-id': faults.wrongVersion ? 'different-version' : object.versionId,
          'content-type': 'application/octet-stream',
          'content-length': body.length,
          'etag': '"deliberately-not-a-content-digest"',
        });
        response.end(body);
        return;
      }
      if (request.method === 'PUT' && url.searchParams.has('legal-hold')) {
        counts.holds++;
        const match =
          /^<LegalHold xmlns="http:\/\/s3\.amazonaws\.com\/doc\/2006-03-01\/"><Status>(ON|OFF)<\/Status><\/LegalHold>$/u.exec(
            bytes.toString('utf8'),
          );
        if (
          !match ||
          createHash('md5').update(bytes).digest('base64') !== request.headers['content-md5']
        ) {
          reject(response, 400, 'InvalidRequest');
          return;
        }
        await persist(holdName(object.versionId), { hold: match[1] });
        if (faults.dropHoldResponse) {
          faults.dropHoldResponse = false;
          request.socket.destroy();
          return;
        }
        response.writeHead(200);
        response.end();
        return;
      }
      reject(response, 405, 'MethodNotAllowed');
    };
    const work = serial.then(processRequest);
    serial = work.catch(() => undefined);
    void work.catch(() => {
      if (!response.destroyed && !response.headersSent) reject(response, 500, 'InternalError');
      else response.destroy();
    });
  });
  await new Promise((resolve, rejectStart) => {
    server.once('error', rejectStart);
    server.listen(port, '127.0.0.1', () => {
      server.removeListener('error', rejectStart);
      resolve();
    });
  });
  let closed = false;
  return {
    endpoint: `http://127.0.0.1:${server.address().port}`,
    faults,
    counts,
    reads,
    objects,
    // Direct fixture controls model external faults; none is a product endpoint.
    async addVersion(original, deleteMarker = false) {
      const object = { ...original, versionId: `v-${randomUUID()}`, deleteMarker };
      await persist(objectName(object.versionId), object, true);
    },
    async rewriteVersion(original, patch) {
      await persist(objectName(original.versionId), { ...original, ...patch });
    },
    async close() {
      if (closed) return;
      closed = true;
      await new Promise((resolve, rejectClose) => {
        server.close((error) => (error ? rejectClose(error) : resolve()));
        server.closeAllConnections();
      });
      await serial;
    },
  };
}
