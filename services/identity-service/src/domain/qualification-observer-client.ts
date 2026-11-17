import { constants } from 'node:fs';
import { open, realpath } from 'node:fs/promises';
import { isIP } from 'node:net';
import { posix } from 'node:path';
import { createHash, createPrivateKey, X509Certificate } from 'node:crypto';
import { Agent, request } from 'node:https';
import { checkServerIdentity, TLSSocket } from 'node:tls';
import { z } from 'zod';

const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
export const qualificationObserverFileSchema = z
  .string()
  .min(2)
  .max(512)
  .refine(
    (p) =>
      p.startsWith('/') &&
      posix.normalize(p) === p &&
      ![...p].some((c) => c.charCodeAt(0) < 32 || c === '\\'),
  );
export const qualificationObserverClientInputSchema = z.strictObject({
  schemaVersion: z.literal(1),
  origin: z.string().refine((value) => {
    try {
      const u = new URL(value);
      return (
        u.protocol === 'https:' &&
        u.origin === value &&
        !u.username &&
        !u.password &&
        isIP(u.hostname) === 4
      );
    } catch {
      return false;
    }
  }),
  serverName: z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$/u),
  serverSpkiDigest: digest,
  clientCertificateDigest: digest,
  caFile: qualificationObserverFileSchema,
  certificateFile: qualificationObserverFileSchema,
  privateKeyFile: qualificationObserverFileSchema,
  observationId: z.uuidv7(),
  operationId: z.uuidv7(),
  requestTimeoutMs: z.number().int().min(30000).max(40000),
  connectWindowMs: z.number().int().min(1000).max(30000),
});
export type QualificationObserverClientInput = z.infer<
  typeof qualificationObserverClientInputSchema
>;
export const qualificationObserverPath = '/internal/v1/installation/deployment-observation';
export const qualificationObserverCommandSchema = z.strictObject({
  schemaVersion: z.literal(1),
  mode: z.enum(['OBSERVE', 'READ_ORIGINAL']),
  observationId: z.uuidv7(),
  operationId: z.uuidv7(),
});
export const qualificationObserverResponseSchema = z
  .strictObject({
    schemaVersion: z.literal(1),
    observationId: z.uuidv7(),
    readback: z.literal('HISTORICAL_ONLY'),
    state: z.enum(['ORIGINAL_RETAINED', 'ORIGINAL_PENDING']),
    observationDigest: digest.nullable(),
  })
  .refine((v) => (v.state === 'ORIGINAL_PENDING') === (v.observationDigest === null));
export type QualificationObserverClientState =
  | 'DISABLED'
  | 'PENDING'
  | 'ORIGINAL_RETAINED'
  | 'ORIGINAL_PENDING'
  | 'UNKNOWN'
  | 'FAILED'
  | 'CLOSED';
const denied = () => new Error('QUALIFICATION_OBSERVER_UNAVAILABLE');
class BeforeHandshakeUnavailable extends Error {}

/** A bounded, owned, single-link regular file, without following path aliases.
 * Shared with the host input loader; never imported from host/Docker code. */
export async function readQualificationObserverFile(
  path: string,
  maximum: number,
): Promise<Buffer> {
  qualificationObserverFileSchema.parse(path);
  if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > 65536) throw denied();
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await file.stat({ bigint: true });
    if (
      !before.isFile() ||
      before.nlink !== 1n ||
      before.size < 1n ||
      before.size > BigInt(maximum) ||
      (before.mode & 0o077n) !== 0n ||
      ![0n, BigInt(process.getuid!())].includes(before.uid) ||
      (await realpath(path)) !== path
    )
      throw denied();
    const buffer = Buffer.alloc(maximum + 1);
    const { bytesRead } = await file.read(buffer, 0, buffer.length, 0);
    const after = await file.stat({ bigint: true });
    if (
      BigInt(bytesRead) !== before.size ||
      bytesRead > maximum ||
      before.size !== after.size ||
      before.ino !== after.ino ||
      before.dev !== after.dev ||
      before.mtimeNs !== after.mtimeNs ||
      before.ctimeNs !== after.ctimeNs
    ) {
      buffer.fill(0);
      throw denied();
    }
    return buffer.subarray(0, bytesRead);
  } finally {
    await file.close();
  }
}
export interface QualificationObserverClient {
  start(): Promise<QualificationObserverClientState>;
  status(): QualificationObserverClientState;
  close(): Promise<void>;
}

/** Optional transport only. No readiness, inspection, database, Docker, key
 * provider or qualification authority. An uncertain original gets ONE read-only
 * recovery request; reconnection never allocates a new operation or observation. */
export async function createQualificationObserverClient(
  path?: string,
): Promise<QualificationObserverClient> {
  let state: QualificationObserverClientState = path === undefined ? 'DISABLED' : 'PENDING';
  let agent: Agent | undefined,
    key: Buffer | undefined,
    config: QualificationObserverClientInput | undefined;
  let pending: Promise<void> | undefined, closing: Promise<void> | undefined;
  const abort = new AbortController();
  try {
    if (path !== undefined) {
      const bytes = await readQualificationObserverFile(path, 16384);
      try {
        config = qualificationObserverClientInputSchema.parse(JSON.parse(bytes.toString('utf8')));
      } finally {
        bytes.fill(0);
      }
      const certificate = await readQualificationObserverFile(config.certificateFile, 16384);
      key = await readQualificationObserverFile(config.privateKeyFile, 16384);
      const ca = await readQualificationObserverFile(config.caFile, 32768);
      const cert = new X509Certificate(certificate),
        now = Date.now();
      if (
        !cert.checkPrivateKey(createPrivateKey(key)) ||
        now < Date.parse(cert.validFrom) ||
        now >= Date.parse(cert.validTo) ||
        'sha256:' + createHash('sha256').update(cert.raw).digest('hex') !==
          config.clientCertificateDigest
      )
        throw denied();
      const expected = config.serverSpkiDigest;
      agent = new Agent({
        cert: certificate,
        key,
        ca,
        minVersion: 'TLSv1.3',
        maxVersion: 'TLSv1.3',
        rejectUnauthorized: true,
        keepAlive: false,
        maxSockets: 1,
        maxTotalSockets: 1,
        maxCachedSessions: 0,
        checkServerIdentity(host, peer) {
          const error = checkServerIdentity(host, peer);
          if (error) return error;
          try {
            const spki = new X509Certificate(peer.raw).publicKey.export({
              type: 'spki',
              format: 'der',
            });
            if ('sha256:' + createHash('sha256').update(spki).digest('hex') !== expected)
              return denied();
          } catch {
            return denied();
          }
          return undefined;
        },
      });
    }
  } catch {
    agent?.destroy();
    key?.fill(0);
    state = 'FAILED';
  }
  const exchange = (mode: 'OBSERVE' | 'READ_ORIGINAL') =>
    new Promise<z.infer<typeof qualificationObserverResponseSchema>>((resolve, reject) => {
      if (!config || !agent || abort.signal.aborted) {
        reject(denied());
        return;
      }
      const body = JSON.stringify(
        qualificationObserverCommandSchema.parse({
          schemaVersion: 1,
          mode,
          observationId: config.observationId,
          operationId: config.operationId,
        }),
      );
      const originalId = config.observationId;
      let authenticated = false;
      const req = request(
        new URL(qualificationObserverPath, config.origin),
        {
          method: 'POST',
          agent,
          servername: config.serverName,
          signal: abort.signal,
          headers: {
            'content-type': 'application/json',
            'content-length': Buffer.byteLength(body),
          },
        },
        (res) => {
          const chunks: Buffer[] = [];
          let length = 0;
          res.on('data', (chunk: Buffer) => {
            length += chunk.length;
            if (length > 8192) {
              req.destroy(denied());
              return;
            }
            chunks.push(chunk);
          });
          res.once('error', () => reject(denied()));
          res.once('end', () => {
            try {
              if (
                res.statusCode !== 200 ||
                res.headers['content-type']?.split(';')[0] !== 'application/json'
              )
                throw denied();
              const result = qualificationObserverResponseSchema.parse(
                JSON.parse(Buffer.concat(chunks).toString('utf8')),
              );
              if (result.observationId !== originalId) throw denied();
              resolve(result);
            } catch {
              reject(denied());
            }
          });
        },
      );
      const timer = setTimeout(() => req.destroy(denied()), config.requestTimeoutMs);
      req.once('close', () => clearTimeout(timer));
      req.once('socket', (socket) => {
        if (socket instanceof TLSSocket)
          socket.once('secureConnect', () => {
            authenticated = true;
          });
      });
      req.once('error', (error) =>
        reject(
          !authenticated &&
            'code' in error &&
            ['ECONNREFUSED', 'ENETUNREACH', 'EHOSTUNREACH'].includes(String(error.code))
            ? new BeforeHandshakeUnavailable()
            : denied(),
        ),
      );
      req.end(body);
    });
  const connect = async (mode: 'OBSERVE' | 'READ_ORIGINAL') => {
    const until = Date.now() + (config?.connectWindowMs ?? 0);
    while (true) {
      try {
        return await exchange(mode);
      } catch (error) {
        if (
          !(error instanceof BeforeHandshakeUnavailable) ||
          Date.now() >= until ||
          abort.signal.aborted
        )
          throw denied();
        await new Promise<void>((resolve) => {
          const end = () => {
            clearTimeout(timer);
            abort.signal.removeEventListener('abort', end);
            resolve();
          };
          const timer = setTimeout(end, 100);
          abort.signal.addEventListener('abort', end, { once: true });
        });
      }
    }
  };
  return Object.freeze({
    status: () => state,
    start() {
      if (state !== 'PENDING' || pending) return (pending ?? Promise.resolve()).then(() => state);
      pending = (async () => {
        try {
          state = (await connect('OBSERVE')).state;
        } catch {
          state = 'UNKNOWN';
          if (!abort.signal.aborted) {
            try {
              state = (await connect('READ_ORIGINAL')).state;
            } catch {
              state = 'UNKNOWN';
            }
          }
        }
      })();
      return pending.then(() => state);
    },
    close() {
      closing ??= (async () => {
        abort.abort();
        agent?.destroy();
        await pending;
        key?.fill(0);
        state = 'CLOSED';
      })();
      return closing;
    },
  });
}
