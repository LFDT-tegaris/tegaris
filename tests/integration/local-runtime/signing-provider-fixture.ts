import { createHash, X509Certificate } from 'node:crypto';
import { createServer, type Server } from 'node:https';
import type { TLSSocket } from 'node:tls';
import { access, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { qualificationCanonicalJson } from '../../../packages/security-kernel/src/operations-configuration/provider-retry-qualification.js';
import {
  createQualificationFixtureStore,
  type QualificationFixtureConfiguration,
} from './signing-provider-qualification-store.js';
import {
  businessProviderRequestSchema,
  type BusinessProviderDescriptor,
} from '../../../services/identity-service/src/domain/business-signing-provider.js';
import {
  createFixtureSigningStore,
  FixtureProviderDenied,
  type FixtureSigningClient,
} from './signing-provider-fixture-store.js';
export type { FixtureSigningClient } from './signing-provider-fixture-store.js';
import {
  createEnvelopeFixtureStore,
  type FixtureEnvelopeSigningConfiguration,
} from './signing-provider-envelope-store.js';

/** Real TLS transport around the independently durable external provider fixture. */
export async function createFixtureSigningProvider(config: {
  readonly root: string;
  readonly certificate: Buffer;
  readonly privateKey: Buffer;
  readonly ca: Buffer;
  readonly clients: readonly FixtureSigningClient[];
  readonly initialKeys: readonly {
    descriptor: BusinessProviderDescriptor;
    privateKeyPkcs8Der: Buffer;
  }[];
  readonly qualification?: QualificationFixtureConfiguration;
  readonly envelope?: FixtureEnvelopeSigningConfiguration;
}): Promise<{
  server: Server;
  close(): Promise<void>;
  qualification?: Awaited<ReturnType<typeof createQualificationFixtureStore>>;
}> {
  const store = await createFixtureSigningStore(config);
  const qualification = config.qualification
    ? await createQualificationFixtureStore(config.root, config.qualification)
    : undefined;
  const envelope = config.envelope
    ? await createEnvelopeFixtureStore(config.root, config.envelope)
    : undefined;
  const clients = new Map(
    config.clients.map((client) => {
      const certificate = new X509Certificate(client.certificate);
      const expectedSan = `URI:urn:openpc:participant:${client.participantId}:workload:${client.workloadId}`;
      if (certificate.subjectAltName !== expectedSan)
        throw new Error('Invalid fixture workload SAN');
      return [createHash('sha256').update(certificate.raw).digest('hex'), client] as const;
    }),
  );
  if (clients.size !== config.clients.length)
    throw new Error('Duplicate fixture workload certificate');
  let serial = Promise.resolve();
  const server = createServer(
    {
      cert: config.certificate,
      key: config.privateKey,
      ca: config.ca,
      requestCert: true,
      rejectUnauthorized: true,
      minVersion: 'TLSv1.3',
      maxVersion: 'TLSv1.3',
    },
    (request, response) => {
      const send = (status: number, value: unknown) => {
        response.writeHead(status, {
          'content-type': 'application/json',
          'cache-control': 'no-store',
        });
        response.end(JSON.stringify(value));
      };
      const peer = request.socket as TLSSocket;
      const raw = peer.getPeerCertificate(true).raw;
      const certificateDigest =
        raw === undefined ? '' : 'sha256:' + createHash('sha256').update(raw).digest('hex');
      const client =
        raw === undefined ? undefined : clients.get(createHash('sha256').update(raw).digest('hex'));
      if (
        !peer.authorized ||
        peer.getProtocol() !== 'TLSv1.3' ||
        (client === undefined &&
          !qualification?.hasClient(certificateDigest) &&
          !envelope?.hasClient(certificateDigest))
      ) {
        send(403, { code: 'DENIED' });
        return;
      }
      serial = serial
        .then(async () => {
          const url = new URL(request.url ?? '/', 'https://fixture.invalid');
          if (envelope && url.pathname.startsWith('/v1/identity-envelope-signing/')) {
            if (
              request.method !== 'POST' ||
              url.search ||
              !envelope.hasClient(certificateDigest) ||
              ![
                '/v1/identity-envelope-signing/perform',
                '/v1/identity-envelope-signing/lookup',
              ].includes(url.pathname)
            ) {
              send(403, { code: 'DENIED' });
              return;
            }
            const chunks: Buffer[] = [];
            let length = 0;
            for await (const chunk of request) {
              const bytes = Buffer.from(chunk);
              length += bytes.length;
              if (length > 196608) {
                send(413, { code: 'TOO_LARGE' });
                return;
              }
              chunks.push(bytes);
            }
            const text = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks));
            const body: unknown = JSON.parse(text);
            if (qualificationCanonicalJson(body) !== text) {
              send(400, { code: 'INVALID_REQUEST' });
              return;
            }
            let result: unknown;
            if (url.pathname.endsWith('/perform')) {
              const signed = await envelope.execute(body, certificateDigest);
              if (signed.drop) {
                response.destroy();
                return;
              }
              result = signed.observation;
            } else result = await envelope.lookup(body, certificateDigest);
            response.writeHead(200, {
              'content-type': 'application/json',
              'cache-control': 'no-store',
            });
            response.end(qualificationCanonicalJson(result));
            return;
          }
          if (qualification && url.pathname.startsWith('/v1/qualification-keys/')) {
            if (
              request.method !== 'POST' ||
              url.search ||
              !qualification.hasClient(certificateDigest) ||
              !['/v1/qualification-keys/observe', '/v1/qualification-keys/lookup'].includes(
                url.pathname,
              )
            ) {
              send(403, { code: 'DENIED' });
              return;
            }
            const chunks: Buffer[] = [];
            let length = 0;
            for await (const chunk of request) {
              const bytes = Buffer.from(chunk);
              length += bytes.length;
              if (length > 196608) {
                send(413, { code: 'TOO_LARGE' });
                return;
              }
              chunks.push(bytes);
            }
            const text = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)),
              body: unknown = JSON.parse(text);
            if (qualificationCanonicalJson(body) !== text) {
              send(400, { code: 'INVALID_REQUEST' });
              return;
            }
            let result: unknown;
            if (url.pathname.endsWith('/observe')) {
              const observed = await qualification.execute(body, certificateDigest);
              if (observed.drop) {
                response.destroy();
                return;
              }
              if (observed.hold) {
                const barrier = join(
                  config.root,
                  'qualification',
                  'faults',
                  observed.observation.attemptId,
                );
                await writeFile(barrier + '.held', '', { mode: 0o600 });
                let released = false;
                const deadline = Date.now() + 4000;
                while (Date.now() < deadline) {
                  try {
                    await access(barrier + '.release');
                    released = true;
                    break;
                  } catch (error) {
                    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
                  }
                  await new Promise((resolve) => setTimeout(resolve, 10));
                }
                if (!released) {
                  response.destroy();
                  return;
                }
              }
              result = observed.observation;
            } else result = await qualification.lookup(body, certificateDigest);
            response.writeHead(200, {
              'content-type': 'application/json',
              'cache-control': 'no-store',
            });
            response.end(qualificationCanonicalJson(result));
            return;
          }
          if (client === undefined) {
            send(403, { code: 'DENIED' });
            return;
          }
          const match = /^\/v1\/business-signing\/attempts\/([0-9a-f-]{36})$/u.exec(url.pathname);
          if (request.method === 'GET' && match !== null) {
            send(200, await store.lookup(match[1]!, client));
            return;
          }
          if (request.method !== 'POST' || url.pathname !== '/v1/business-signing/requests') {
            send(404, { code: 'NOT_FOUND' });
            return;
          }
          let body = '';
          for await (const chunk of request) {
            body += chunk;
            if (Buffer.byteLength(body) > 262144) {
              send(413, { code: 'TOO_LARGE' });
              return;
            }
          }
          const parsed = businessProviderRequestSchema.safeParse(JSON.parse(body));
          if (!parsed.success) {
            send(400, { code: 'INVALID_REQUEST' });
            return;
          }
          const result = await store.execute(parsed.data, client);
          if (result.drop) {
            response.destroy();
            return;
          }
          if (result.delayMs > 0)
            await new Promise((resolve) => setTimeout(resolve, result.delayMs));
          send(200, result.observation);
        })
        .catch((error) => {
          if (!response.headersSent)
            send(error instanceof FixtureProviderDenied ? 403 : 503, {
              code: error instanceof FixtureProviderDenied ? 'DENIED' : 'PROVIDER_UNAVAILABLE',
            });
          else response.destroy();
        });
    },
  );
  return {
    server,
    ...(qualification ? { qualification } : {}),
    async close() {
      server.closeAllConnections();
      await new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
      await serial;
    },
  };
}
