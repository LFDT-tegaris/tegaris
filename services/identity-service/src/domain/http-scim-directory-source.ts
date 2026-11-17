import { Agent, request as httpsRequest } from 'node:https';
import { performance } from 'node:perf_hooks';
import { z } from 'zod';
import {
  parseScimResource,
  scimListSchema,
  scimResourceIdSchema,
  ScimDirectoryUnavailable,
  type ScimDirectorySource,
  type ScimResourceObservation,
} from './scim-directory-source.js';

const kindSchema = z.enum(['Users', 'Groups']);
const maxResponseBytes = 1_048_576;
const pageSize = 100;
const maxResources = 5000;

/** The owning runtime resolves the registered profile's exact-version secrets server-side. */
export function createHttpScimDirectorySource(config: {
  readonly profileId: string;
  readonly baseUrl: string;
  readonly certificate: Buffer;
  readonly privateKey: Buffer;
  readonly trustCa: Buffer;
  readonly timeoutMs?: number;
}): ScimDirectorySource {
  const base = new URL(config.baseUrl);
  const timeoutMs = config.timeoutMs ?? 5000;
  if (
    !z.uuid().safeParse(config.profileId).success ||
    base.protocol !== 'https:' ||
    base.username ||
    base.password ||
    base.search ||
    base.hash ||
    !config.certificate.length ||
    !config.privateKey.length ||
    !config.trustCa.length ||
    !Number.isSafeInteger(timeoutMs) ||
    timeoutMs < 50 ||
    timeoutMs > 10_000
  )
    throw new Error('Invalid registered SCIM transport configuration');
  base.pathname = `${base.pathname.replace(/\/+$/u, '')}/`;
  const agent = new Agent({
    cert: config.certificate,
    key: config.privateKey,
    ca: config.trustCa,
    minVersion: 'TLSv1.3',
    maxVersion: 'TLSv1.3',
    rejectUnauthorized: true,
    keepAlive: true,
    maxSockets: 1,
    maxFreeSockets: 1,
  });
  let closed = false;
  let busy = false;
  async function exclusively<T>(operation: () => Promise<T>): Promise<T> {
    if (closed || busy) throw new ScimDirectoryUnavailable();
    busy = true;
    try {
      return await operation();
    } catch {
      throw new ScimDirectoryUnavailable();
    } finally {
      busy = false;
    }
  }
  function exchange(
    url: URL,
    deadline: number,
  ): Promise<{ body: unknown; bytes: number; etag?: string }> {
    return new Promise((resolve, reject) => {
      const remaining = Math.min(timeoutMs, Math.floor(deadline - performance.now()));
      if (remaining <= 0) {
        reject(new ScimDirectoryUnavailable());
        return;
      }
      const request = httpsRequest(
        url,
        {
          method: 'GET',
          agent,
          headers: { 'accept': 'application/scim+json', 'accept-encoding': 'identity' },
        },
        (response) => {
          const rejectResponse = () => {
            response.destroy();
            reject(new ScimDirectoryUnavailable());
          };
          // No redirects, automatic retries, or treating 404/authentication failure as deletion.
          // A separate contract must establish an explicit provider deletion before local removal.
          const type = response.headers['content-type']?.split(';')[0]?.trim().toLowerCase();
          if (
            response.statusCode !== 200 ||
            type !== 'application/scim+json' ||
            (response.headers['content-encoding'] &&
              response.headers['content-encoding'] !== 'identity') ||
            Number(response.headers['content-length'] ?? 0) > maxResponseBytes
          ) {
            rejectResponse();
            return;
          }
          const chunks: Buffer[] = [];
          let length = 0;
          response.on('data', (chunk: Buffer) => {
            length += chunk.length;
            if (length > maxResponseBytes) {
              rejectResponse();
              return;
            }
            chunks.push(chunk);
          });
          response.once('aborted', rejectResponse);
          response.once('error', () => reject(new ScimDirectoryUnavailable()));
          response.once('end', () => {
            try {
              if (!response.complete) throw new ScimDirectoryUnavailable();
              resolve({
                body: JSON.parse(
                  new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)),
                ),
                bytes: length,
                ...(response.headers.etag === undefined ? {} : { etag: response.headers.etag }),
              });
            } catch {
              rejectResponse();
            }
          });
        },
      );
      // Total per-request deadline includes a peer trickling bytes; enumeration has its own total budget.
      const timer = setTimeout(() => {
        request.destroy();
        reject(new ScimDirectoryUnavailable());
      }, remaining);
      request.once('close', () => clearTimeout(timer));
      request.once('error', () => reject(new ScimDirectoryUnavailable()));
      request.end();
    });
  }
  return {
    profileId: config.profileId,
    baseUrl: base.href,
    enumerate(kind) {
      return exclusively(async () => {
        kindSchema.parse(kind);
        const deadline = performance.now() + 30_000;
        const resources: ScimResourceObservation[] = [];
        const seen = new Set<string>();
        let startIndex = 1;
        let total: number | undefined;
        let bytes = 0;
        do {
          const url = new URL(kind, base);
          url.searchParams.set('startIndex', String(startIndex));
          url.searchParams.set('count', String(pageSize));
          const response = await exchange(url, deadline);
          bytes += response.bytes;
          if (bytes > 8 * maxResponseBytes) throw new ScimDirectoryUnavailable();
          const page = scimListSchema.parse(response.body);
          const values = page.Resources ?? [];
          if (
            page.totalResults > maxResources ||
            (total !== undefined && page.totalResults !== total) ||
            (page.totalResults > 0 &&
              (page.startIndex !== startIndex || page.itemsPerPage !== values.length)) ||
            (page.totalResults === 0 && (values.length !== 0 || (page.itemsPerPage ?? 0) !== 0)) ||
            values.length > pageSize ||
            (values.length === 0 && page.totalResults >= startIndex) ||
            resources.length + values.length > page.totalResults
          )
            throw new ScimDirectoryUnavailable();
          total = page.totalResults;
          for (const raw of values) {
            const resource = parseScimResource(kind, raw);
            if (seen.has(resource.id)) throw new ScimDirectoryUnavailable();
            seen.add(resource.id);
            resources.push(resource);
          }
          startIndex += values.length;
        } while (resources.length < total);
        return {
          profileId: config.profileId,
          kind,
          observedAt: new Date().toISOString(),
          resources,
          omissionMeaning: 'NONE' as const,
        };
      });
    },
    read(kind, id) {
      return exclusively(async () => {
        kindSchema.parse(kind);
        scimResourceIdSchema.parse(id);
        const response = await exchange(
          new URL(`${kind}/${encodeURIComponent(id)}`, base),
          performance.now() + timeoutMs,
        );
        const resource = parseScimResource(kind, response.body);
        if (resource.id !== id || response.etag !== resource.version)
          throw new ScimDirectoryUnavailable();
        return resource;
      });
    },
    close() {
      closed = true;
      agent.destroy();
    },
  };
}
