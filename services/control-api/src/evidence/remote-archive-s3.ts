import { createHash, createHmac } from 'node:crypto';
import { AsyncLocalStorage } from 'node:async_hooks';
import { z } from 'zod';
import {
  RemoteArchiveError,
  remoteArchiveProfile,
  remoteVersionId,
  type RemoteArchiveProfile,
} from './remote-archive-contracts.js';
import { MAX_SEGMENT_BYTES } from './segment.js';

export const s3ArchiveCredentials = z.strictObject({
  accessKeyId: z.string().regex(/^[A-Za-z0-9]{16,128}$/u),
  secretAccessKey: z.string().min(16).max(256),
  sessionToken: z.string().min(1).max(8192).optional(),
});
export type S3ArchiveCredentials = z.infer<typeof s3ArchiveCredentials>;
const hash = (value: string | Buffer) => createHash('sha256').update(value).digest('hex');
const hmac = (key: string | Buffer, value: string) =>
  createHmac('sha256', key).update(value).digest();
const encode = (value: string) =>
  encodeURIComponent(value).replace(
    /[!'()*]/gu,
    (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`,
  );
const order = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

/** S3 SigV4 signed payload, single chunk. No redirects, presigned URLs or retries.
 * https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
 * Exported for the independent published signing-vector regression.
 */
export function signS3Request(
  method: string,
  url: URL,
  headers: Readonly<Record<string, string>>,
  body: Buffer,
  region: string,
  credentials: S3ArchiveCredentials,
  now: Date,
) {
  const date = now.toISOString().replace(/[:-]|\.\d{3}/gu, '');
  const signed: Record<string, string> = {
    ...headers,
    'host': url.host,
    'x-amz-date': date,
    'x-amz-content-sha256': hash(body),
    ...(credentials.sessionToken ? { 'x-amz-security-token': credentials.sessionToken } : {}),
  };
  const names = Object.keys(signed).sort(order);
  const canonicalHeaders = names
    .map((name) => `${name}:${signed[name]!.trim().replace(/\s+/gu, ' ')}\n`)
    .join('');
  const query = [...url.searchParams]
    .map(([key, value]) => [encode(key), encode(value)] as const)
    .sort((a, b) => order(a[0], b[0]) || order(a[1], b[1]))
    .map(([key, value]) => `${key}=${value}`)
    .join('&');
  const scope = `${date.slice(0, 8)}/${region}/s3/aws4_request`;
  const canonical = [
    method,
    url.pathname,
    query,
    canonicalHeaders,
    names.join(';'),
    hash(body),
  ].join('\n');
  const signingKey = hmac(
    hmac(hmac(hmac(`AWS4${credentials.secretAccessKey}`, date.slice(0, 8)), region), 's3'),
    'aws4_request',
  );
  const signature = hmac(
    signingKey,
    `AWS4-HMAC-SHA256\n${date}\n${scope}\n${hash(canonical)}`,
  ).toString('hex');
  signingKey.fill(0);
  return {
    ...signed,
    authorization: `AWS4-HMAC-SHA256 Credential=${credentials.accessKeyId}/${scope},SignedHeaders=${names.join(';')},Signature=${signature}`,
  };
}

type XmlNode = { name: string; text: string; children: XmlNode[] };
const xmlNamespace = 'http://s3.amazonaws.com/doc/2006-03-01/';
function xmlDecode(value: string) {
  if (/&(?!amp;|lt;|gt;|quot;|apos;|#\d+;|#x[0-9a-fA-F]+;)/u.test(value))
    throw new RemoteArchiveError('INTEGRITY');
  return value.replace(/&(amp|lt|gt|quot|apos|#\d+|#x[0-9a-fA-F]+);/gu, (_, entity: string) => {
    const predefined: Record<string, string> = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" };
    if (predefined[entity]) return predefined[entity]!;
    const code = entity.startsWith('#x')
      ? Number.parseInt(entity.slice(2), 16)
      : Number(entity.slice(1));
    if (!(
      code === 9 ||
      code === 10 ||
      code === 13 ||
      (code >= 32 && code <= 0xd7ff) ||
      (code >= 0xe000 && code <= 0xfffd) ||
      (code >= 0x10000 && code <= 0x10ffff)
    ))
      throw new RemoteArchiveError('INTEGRITY');
    return String.fromCodePoint(code);
  });
}
/** Bounded S3 response subset. DTDs/entities/CDATA, mixed content, duplicate
 * required fields and unsupported attributes fail closed; no general XML engine.
 */
function parseXml(bytes: Buffer, rootName: string): XmlNode {
  const input = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  if (
    input.length > 1024 * 1024 ||
    [...input].some((char) => char.charCodeAt(0) < 32 && ![9, 10, 13].includes(char.charCodeAt(0)))
  )
    throw new RemoteArchiveError('INTEGRITY');
  const text = input.replace(
    /^<\?xml version=["']1\.0["'](?: encoding=["']UTF-8["'])?\s*\?>\s*/u,
    '',
  );
  const stack: XmlNode[] = [];
  let root: XmlNode | undefined,
    consumed = 0,
    nodes = 0;
  for (const match of text.matchAll(/<[^>]*>|[^<]+/gu)) {
    if (match.index !== consumed) throw new RemoteArchiveError('INTEGRITY');
    const token = match[0];
    consumed += token.length;
    if (!token.startsWith('<')) {
      if (stack.length) stack[stack.length - 1]!.text += xmlDecode(token);
      else if (token.trim()) throw new RemoteArchiveError('INTEGRITY');
    } else if (token.startsWith('</')) {
      const top = stack.pop();
      if (!top || token !== `</${top.name}>`) throw new RemoteArchiveError('INTEGRITY');
      if (top.children.length && top.text.trim()) throw new RemoteArchiveError('INTEGRITY');
    } else {
      const opening =
        /^<([A-Za-z][A-Za-z0-9]*)(?: xmlns="(http:\/\/s3\.amazonaws\.com\/doc\/2006-03-01\/)")?\s*(\/?)>$/u.exec(
          token,
        );
      if (!opening || (opening[2] && stack.length) || ++nodes > 8192 || stack.length >= 12)
        throw new RemoteArchiveError('INTEGRITY');
      const node: XmlNode = { name: opening[1]!, text: '', children: [] };
      if (stack.length) stack[stack.length - 1]!.children.push(node);
      else {
        if (root) throw new RemoteArchiveError('INTEGRITY');
        root = node;
      }
      if (!opening[3]) stack.push(node);
    }
  }
  if (consumed !== text.length || stack.length || !root || root.name !== rootName)
    throw new RemoteArchiveError('INTEGRITY');
  return root;
}
function xml(bytes: Buffer, rootName: string) {
  try {
    return parseXml(bytes, rootName);
  } catch {
    throw new RemoteArchiveError('INTEGRITY');
  }
}
function version(value: unknown) {
  const parsed = remoteVersionId.safeParse(value);
  if (!parsed.success) throw new RemoteArchiveError('INTEGRITY');
  return parsed.data;
}
function decodedKey(value: string) {
  try {
    return decodeURIComponent(value);
  } catch {
    throw new RemoteArchiveError('INTEGRITY');
  }
}
function field(node: XmlNode, name: string, optional = false) {
  const found = node.children.filter((child) => child.name === name);
  if (optional && found.length === 0) return undefined;
  if (found.length !== 1 || found[0]!.children.length) throw new RemoteArchiveError('INTEGRITY');
  return found[0]!.text;
}
function required(node: XmlNode, name: string) {
  return field(node, name)!;
}

class S3StatusError extends Error {
  constructor(readonly status: number) {
    super('Archive request rejected');
  }
}

export class S3ArchiveTransport {
  private readonly operationSignal = new AsyncLocalStorage<{
    signal: AbortSignal;
    deadlineMs: number;
  }>();

  /** Every HTTP request in one append/readback shares the signed timeout.
   * Nested verification never renews that deadline. Context is per transport
   * and async operation, so cancelling one call cannot cancel another. */
  async withinDeadline<T>(
    work: () => Promise<T>,
    signal?: AbortSignal,
    admittedDeadlineMs?: number,
  ): Promise<T> {
    const inherited = this.operationSignal.getStore();
    const deadlineMs = Math.min(
      inherited?.deadlineMs ?? performance.now() + this.profile.requestTimeoutMs,
      admittedDeadlineMs ?? Infinity,
    );
    if (!Number.isFinite(deadlineMs) || deadlineMs <= performance.now())
      throw new RemoteArchiveError('UNAVAILABLE');
    const deadline = inherited?.signal ?? AbortSignal.timeout(this.profile.requestTimeoutMs);
    const combined = signal ? AbortSignal.any([deadline, signal]) : deadline;
    if (combined.aborted) throw new RemoteArchiveError('UNAVAILABLE');
    return this.operationSignal.run({ signal: combined, deadlineMs }, work);
  }

  private async credentialsWithinDeadline(signal: AbortSignal) {
    let abort: (() => void) | undefined;
    try {
      const cancelled = new Promise<never>((_, reject) => {
        abort = () => reject(new RemoteArchiveError('UNAVAILABLE'));
        signal.addEventListener('abort', abort, { once: true });
        if (signal.aborted) abort();
      });
      return await Promise.race([this.credentials(), cancelled]);
    } finally {
      if (abort) signal.removeEventListener('abort', abort);
    }
  }
  readonly profile: RemoteArchiveProfile;
  constructor(
    profile: RemoteArchiveProfile,
    private readonly credentials: () => Promise<S3ArchiveCredentials>,
  ) {
    this.profile = remoteArchiveProfile.parse(profile);
  }

  private async request(
    method: 'GET' | 'PUT',
    key: string | null,
    query: Record<string, string>,
    headers: Record<string, string> = {},
    body: Buffer = Buffer.alloc(0),
  ) {
    const url = new URL(this.profile.endpoint);
    url.pathname = `/${this.profile.bucket}${key === null ? '' : `/${key.split('/').map(encode).join('/')}`}`;
    for (const [name, value] of Object.entries(query)) url.searchParams.set(name, value);
    const window = this.operationSignal.getStore();
    const signal = window?.signal ?? AbortSignal.timeout(this.profile.requestTimeoutMs);
    const deadlineMs = window?.deadlineMs ?? performance.now() + this.profile.requestTimeoutMs;
    const fresh = () => {
      signal.throwIfAborted();
      if (performance.now() >= deadlineMs) throw new RemoteArchiveError('UNAVAILABLE');
    };
    let dispatched = false;
    try {
      fresh();
      const credentials = s3ArchiveCredentials.parse(await this.credentialsWithinDeadline(signal));
      fresh();
      const signed = signS3Request(
        method,
        url,
        {
          ...headers,
          'x-amz-expected-bucket-owner': this.profile.expectedBucketOwner,
        },
        body,
        this.profile.region,
        credentials,
        new Date(),
      );
      fresh();
      dispatched = true;
      const response = await fetch(url, {
        method,
        headers: signed,
        ...(method === 'PUT' ? { body: new Uint8Array(body) } : {}),
        redirect: 'manual',
        signal,
      });
      if (response.status !== 200) {
        await response.body?.cancel();
        throw new S3StatusError(response.status);
      }
      if (response.headers.has('content-encoding')) {
        await response.body?.cancel();
        throw new RemoteArchiveError('INTEGRITY');
      }
      const reader = response.body?.getReader(),
        chunks: Buffer[] = [];
      let size = 0;
      if (reader) {
        try {
          for (;;) {
            const part = await reader.read();
            if (part.done) break;
            size += part.value.length;
            if (size > MAX_SEGMENT_BYTES) throw new RemoteArchiveError('INTEGRITY');
            chunks.push(Buffer.from(part.value));
          }
        } finally {
          await reader.cancel();
        }
      }
      return { headers: response.headers, bytes: Buffer.concat(chunks) };
    } catch (error) {
      if (error instanceof RemoteArchiveError || error instanceof S3StatusError) throw error;
      throw new RemoteArchiveError(method === 'PUT' && dispatched ? 'AMBIGUOUS' : 'UNAVAILABLE');
    }
  }

  private async read(key: string, query: Record<string, string>) {
    try {
      return await this.request('GET', key, query);
    } catch (error) {
      if (error instanceof S3StatusError) throw new RemoteArchiveError('UNAVAILABLE');
      throw error;
    }
  }

  async put(
    key: string,
    bytes: Buffer,
    metadata: Record<string, string>,
    retention: string,
    hold: 'ON' | 'OFF',
  ): Promise<string | null> {
    try {
      const result = await this.request(
        'PUT',
        key,
        {},
        {
          ...Object.fromEntries(
            Object.entries(metadata).map(([name, value]) => [`x-amz-meta-${name}`, value]),
          ),
          'content-type': 'application/octet-stream',
          'content-md5': createHash('md5').update(bytes).digest('base64'),
          'if-none-match': '*',
          'x-amz-object-lock-mode': 'COMPLIANCE',
          'x-amz-object-lock-retain-until-date': retention,
          'x-amz-object-lock-legal-hold': hold,
        },
        bytes,
      );
      const parsed = remoteVersionId.safeParse(result.headers.get('x-amz-version-id'));
      if (!parsed.success) throw new RemoteArchiveError('AMBIGUOUS');
      return parsed.data;
    } catch (error) {
      if (error instanceof S3StatusError) {
        if (error.status === 412 || error.status === 409) return null;
        // Even an HTTP failure cannot be used as proof that an earlier send had no effect.
        throw new RemoteArchiveError(error.status >= 500 ? 'AMBIGUOUS' : 'UNAVAILABLE');
      }
      throw error;
    }
  }

  async readExact(key: string, versionId: string) {
    version(versionId);
    const result = await this.read(key, { versionId });
    if (
      result.headers.get('x-amz-version-id') !== versionId ||
      result.headers.get('x-amz-delete-marker') === 'true'
    )
      throw new RemoteArchiveError('INTEGRITY');
    return result;
  }

  async protection(key: string, versionId: string) {
    version(versionId);
    const retention = xml((await this.read(key, { retention: '', versionId })).bytes, 'Retention');
    const hold = xml((await this.read(key, { 'legal-hold': '', versionId })).bytes, 'LegalHold');
    const mode = required(retention, 'Mode'),
      retainUntil = required(retention, 'RetainUntilDate');
    const legalHold = required(hold, 'Status');
    if (mode !== 'COMPLIANCE' || !['ON', 'OFF'].includes(legalHold))
      throw new RemoteArchiveError('PROTECTION_MISMATCH');
    return { mode: 'COMPLIANCE' as const, retainUntil, legalHold: legalHold as 'ON' | 'OFF' };
  }

  async setLegalHold(key: string, versionId: string, hold: 'ON' | 'OFF') {
    version(versionId);
    const bytes = Buffer.from(
      `<LegalHold xmlns="${xmlNamespace}"><Status>${hold}</Status></LegalHold>`,
    );
    try {
      await this.request(
        'PUT',
        key,
        { 'legal-hold': '', versionId },
        {
          'content-type': 'application/xml',
          'content-md5': createHash('md5').update(bytes).digest('base64'),
        },
        bytes,
      );
    } catch (error) {
      if (error instanceof S3StatusError)
        throw new RemoteArchiveError(error.status >= 500 ? 'AMBIGUOUS' : 'UNAVAILABLE');
      throw error;
    }
  }

  /** Discovery never returns an absence certificate. Every page must be complete
   * and bound to the requested key. Delete markers and multiple versions conflict.
   */
  async discoverVersions(key: string) {
    let marker: { key: string; version: string } | undefined;
    const seen = new Set<string>(),
      versions: string[] = [];
    for (let page = 0; page < this.profile.maxVersionPages; page++) {
      let bytes: Buffer;
      try {
        bytes = (
          await this.request('GET', null, {
            'versions': '',
            'prefix': key,
            'encoding-type': 'url',
            'max-keys': '100',
            ...(marker ? { 'key-marker': marker.key, 'version-id-marker': marker.version } : {}),
          })
        ).bytes;
      } catch (error) {
        if (error instanceof S3StatusError) throw new RemoteArchiveError('UNAVAILABLE');
        throw error;
      }
      const result = xml(bytes, 'ListVersionsResult');
      if (
        required(result, 'Name') !== this.profile.bucket ||
        required(result, 'EncodingType') !== 'url' ||
        decodedKey(required(result, 'Prefix')) !== key
      )
        throw new RemoteArchiveError('INTEGRITY');
      if (result.children.some((entry) => ['DeleteMarker', 'CommonPrefixes'].includes(entry.name)))
        throw new RemoteArchiveError('CONFLICT');
      for (const entry of result.children.filter((entry) => entry.name === 'Version')) {
        if (decodedKey(required(entry, 'Key')) !== key) throw new RemoteArchiveError('CONFLICT');
        const versionId = version(required(entry, 'VersionId'));
        if (versions.includes(versionId)) throw new RemoteArchiveError('INTEGRITY');
        versions.push(versionId);
        if (versions.length > 1) throw new RemoteArchiveError('CONFLICT');
      }
      const truncated = required(result, 'IsTruncated');
      if (truncated === 'false') return versions;
      if (truncated !== 'true') throw new RemoteArchiveError('INTEGRITY');
      const next = {
        key: decodedKey(required(result, 'NextKeyMarker')),
        version: version(required(result, 'NextVersionIdMarker')),
      };
      const token = JSON.stringify(next);
      if (next.key !== key || seen.has(token)) throw new RemoteArchiveError('INTEGRITY');
      seen.add(token);
      marker = next;
    }
    throw new RemoteArchiveError('AMBIGUOUS');
  }
}
