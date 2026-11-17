import { execFile } from 'node:child_process';
import { X509Certificate, timingSafeEqual } from 'node:crypto';
import { chmod, mkdir, mkdtemp, readFile, rm } from 'node:fs/promises';
import { createServer, type Server } from 'node:https';
import type { Duplex } from 'node:stream';
import { join } from 'node:path';
import { TLSSocket } from 'node:tls';
import { promisify, types } from 'node:util';

const execFileAsync = promisify(execFile);
const openssl = '/usr/bin/openssl';
export const gate3OpenSslVersion =
  'OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024)';
const acceptedClientCommonName = 'openpc-i07-gate3-client';

export const gate3EndpointPaths = Object.freeze({
  read: '/v1/privacy-explorer/projection:read',
  verify: '/v1/privacy-explorer/evidence:verify',
});
const admittedPaths: readonly string[] = Object.freeze(Object.values(gate3EndpointPaths));

export type Gate3ResponseMode =
  'NORMAL' | 'DELAYED' | 'NEVER_SETTLE' | 'LATE_CHUNKS' | 'MANY_CHUNKS';
export type Gate3WireVector = Readonly<{
  path: string;
  expectedBody: Uint8Array;
  statusCode: number;
  contentType: string;
  body: Uint8Array;
  maximumCalls: number;
  responseMode?: Gate3ResponseMode;
  delayMilliseconds?: number;
  responseChunkBytes?: number;
  location?: string;
}>;

type CapturedCall = Readonly<{
  path: string;
  method: string;
  contentType: string;
  tlsProtocol: string;
  clientCommonName: string;
  body: Uint8Array;
}>;

export type Gate3ConformantEndpoint = Readonly<{
  origin: string;
  privateMaterialRoot: string;
  trustAnchorPem: Uint8Array;
  acceptedClientCertificatePem: Uint8Array;
  acceptedClientPrivateKeyPem: Uint8Array;
  wrongClientCertificatePem: Uint8Array;
  wrongClientPrivateKeyPem: Uint8Array;
  sameNameWrongClientCertificatePem: Uint8Array;
  sameNameWrongClientPrivateKeyPem: Uint8Array;
  untrustedClientCertificatePem: Uint8Array;
  untrustedClientPrivateKeyPem: Uint8Array;
  serverCertificatePem: Uint8Array;
  calls(): readonly CapturedCall[];
  startedResponseCount(): number;
  completedResponseCount(): number;
  pendingTimerCount(): number;
  openSocketCount(): number;
  networkInventory(): Readonly<{
    protocol: 'https:';
    host: '127.0.0.1';
    port: number;
    paths: readonly string[];
  }>;
  close(): Promise<void>;
}>;

type OwnedVector = Readonly<{
  path: string;
  expectedBody: Uint8Array;
  statusCode: number;
  contentType: string;
  body: Uint8Array;
  maximumCalls: number;
  responseMode: Gate3ResponseMode;
  delayMilliseconds: number;
  responseChunkBytes: number;
  location?: string;
}>;

const byteArrayPrototypes = new Set([Buffer.prototype, Uint8Array.prototype]);
const ownByteArray = (value: unknown, label: string) => {
  if (
    types.isProxy(value) ||
    !(value instanceof Uint8Array) ||
    !byteArrayPrototypes.has(Object.getPrototypeOf(value))
  )
    throw new Error(`${label}: exact built-in byte array required`);
  const keys = Reflect.ownKeys(value);
  if (
    keys.some((key) => typeof key !== 'string' || !/^(?:0|[1-9]\d*)$/.test(key)) ||
    Object.values(Object.getOwnPropertyDescriptors(value)).some(
      (descriptor) => !Object.hasOwn(descriptor, 'value') || descriptor.get || descriptor.set,
    )
  )
    throw new Error(`${label}: byte array overrides are forbidden`);
  return Uint8Array.from(value);
};

const run = async (arguments_: readonly string[], cwd: string) => {
  await execFileAsync(openssl, arguments_, { cwd, encoding: 'utf8' });
};

const requireOwnDataDescriptors = (value: unknown, label: string) => {
  if (!value || typeof value !== 'object' || Array.isArray(value) || types.isProxy(value))
    throw new Error(`${label}: expected a non-proxy object`);
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null)
    throw new Error(`${label}: invalid prototype`);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (
    Reflect.ownKeys(value).some((key) => typeof key !== 'string') ||
    Object.values(descriptors).some(
      (descriptor) => !Object.hasOwn(descriptor, 'value') || descriptor.get || descriptor.set,
    )
  )
    throw new Error(`${label}: own data properties required`);
  return descriptors;
};

const ownVectors = (input: readonly Gate3WireVector[]): readonly OwnedVector[] => {
  if (!Array.isArray(input) || types.isProxy(input) || input.length !== admittedPaths.length)
    throw new Error('Gate 3 endpoint requires one vector for each admitted B01 path');
  const owned = input.map((candidate, index) => {
    const descriptors = requireOwnDataDescriptors(candidate, `Gate 3 vector ${index}`);
    const required = ['body', 'contentType', 'expectedBody', 'maximumCalls', 'path', 'statusCode'];
    const optional = ['delayMilliseconds', 'location', 'responseChunkBytes', 'responseMode'];
    const keys = Object.keys(descriptors).sort();
    if (
      required.some((key) => !Object.hasOwn(descriptors, key)) ||
      keys.some((key) => !required.includes(key) && !optional.includes(key))
    )
      throw new Error(`Gate 3 vector ${index}: invalid fields`);
    const get = (key: string) => descriptors[key]?.value as unknown;
    const path = get('path');
    const expectedBody = get('expectedBody');
    const statusCode = get('statusCode');
    const contentType = get('contentType');
    const body = get('body');
    const maximumCalls = get('maximumCalls');
    const responseMode = (get('responseMode') ?? 'NORMAL') as Gate3ResponseMode;
    const delayMilliseconds = get('delayMilliseconds') ?? 0;
    const responseChunkBytes = get('responseChunkBytes') ?? 1;
    const location = get('location');
    if (
      typeof path !== 'string' ||
      !admittedPaths.includes(path) ||
      typeof contentType !== 'string' ||
      contentType.length < 1 ||
      typeof statusCode !== 'number' ||
      !Number.isSafeInteger(statusCode) ||
      statusCode < 100 ||
      statusCode > 599 ||
      typeof maximumCalls !== 'number' ||
      !Number.isSafeInteger(maximumCalls) ||
      maximumCalls < 1 ||
      !['NORMAL', 'DELAYED', 'NEVER_SETTLE', 'LATE_CHUNKS', 'MANY_CHUNKS'].includes(responseMode) ||
      typeof delayMilliseconds !== 'number' ||
      !Number.isSafeInteger(delayMilliseconds) ||
      delayMilliseconds < 0 ||
      delayMilliseconds > 10_000 ||
      typeof responseChunkBytes !== 'number' ||
      !Number.isSafeInteger(responseChunkBytes) ||
      responseChunkBytes < 1 ||
      responseChunkBytes > 65_536 ||
      (responseMode === 'NORMAL' && delayMilliseconds !== 0) ||
      (responseMode !== 'NORMAL' &&
        responseMode !== 'NEVER_SETTLE' &&
        responseMode !== 'MANY_CHUNKS' &&
        delayMilliseconds < 1) ||
      (location !== undefined && (typeof location !== 'string' || location.length < 1))
    )
      throw new Error(`Gate 3 vector ${index}: invalid value`);
    const ownedExpectedBody = ownByteArray(expectedBody, `Gate 3 vector ${index} expectedBody`);
    const ownedBody = ownByteArray(body, `Gate 3 vector ${index} body`);
    return Object.freeze({
      path,
      expectedBody: ownedExpectedBody,
      statusCode,
      contentType,
      body: ownedBody,
      maximumCalls,
      responseMode,
      delayMilliseconds,
      responseChunkBytes,
      ...(location === undefined ? {} : { location }),
    });
  });
  if (
    new Set(owned.map(({ path }) => path)).size !== owned.length ||
    admittedPaths.some((path) => !owned.some((vector) => vector.path === path))
  )
    throw new Error('Gate 3 endpoint requires unique vectors for every admitted B01 path');
  return Object.freeze(owned);
};

const generateIdentity = async (
  directory: string,
  name: string,
  commonName: string,
  san?: string,
) => {
  await run(['genrsa', '-out', `${name}.key`, '2048'], directory);
  await chmod(join(directory, `${name}.key`), 0o600);
  await run(
    [
      'req',
      '-new',
      '-key',
      `${name}.key`,
      '-out',
      `${name}.csr`,
      '-subj',
      `/CN=${commonName}`,
      ...(san ? ['-addext', `subjectAltName=${san}`] : []),
    ],
    directory,
  );
  await run(
    [
      'x509',
      '-req',
      '-in',
      `${name}.csr`,
      '-CA',
      'ca.crt',
      '-CAkey',
      'ca.key',
      '-CAcreateserial',
      '-out',
      `${name}.crt`,
      '-days',
      '1',
      '-sha256',
      ...(san ? ['-copy_extensions', 'copy'] : []),
    ],
    directory,
  );
};

const closeServer = (server: Server) =>
  new Promise<void>((resolve) => {
    server.close(() => resolve());
    server.closeAllConnections();
  });

const listenOnDynamicLocalPort = async (server: Server) => {
  const firstPort = 49_152 + (process.pid % 16_384);
  for (let attempt = 0; attempt < 128; attempt += 1) {
    const port = 49_152 + ((firstPort - 49_152 + attempt) % 16_384);
    const listening = await new Promise<boolean>((resolve, reject) => {
      const onError = (error: NodeJS.ErrnoException) => {
        server.off('listening', onListening);
        if (error.code === 'EADDRINUSE') resolve(false);
        else reject(error);
      };
      const onListening = () => {
        server.off('error', onError);
        resolve(true);
      };
      server.once('error', onError);
      server.once('listening', onListening);
      server.listen(port, '127.0.0.1');
    });
    if (listening) return;
  }
  throw new Error('failed to bind an admitted local dynamic port');
};

export const createGate3ConformantEndpoint = async (
  vectors: readonly Gate3WireVector[],
): Promise<Gate3ConformantEndpoint> => {
  const ownedVectors = ownVectors(vectors);
  const externalRoot = process.env.OPENPC_PNC_TMP_ROOT;
  if (!externalRoot) throw new Error('OPENPC_PNC_TMP_ROOT is required');
  const version = await execFileAsync(openssl, ['version'], { encoding: 'utf8' });
  if (version.stdout.trim() !== gate3OpenSslVersion)
    throw new Error('OpenSSL fixture tool drifted');
  await mkdir(externalRoot, { recursive: true, mode: 0o700 });
  const trustRoot = await mkdtemp(join(externalRoot, 'i07-gate3-trust-'));
  await chmod(trustRoot, 0o700);
  let server: Server | undefined;
  const sockets = new Set<Duplex>();
  const timers = new Set<NodeJS.Timeout>();
  const schedule = (task: () => void, milliseconds: number) => {
    const timer = setTimeout(() => {
      timers.delete(timer);
      task();
    }, milliseconds);
    timers.add(timer);
  };
  try {
    await run(['genrsa', '-out', 'ca.key', '2048'], trustRoot);
    await chmod(join(trustRoot, 'ca.key'), 0o600);
    await run(
      [
        'req',
        '-x509',
        '-new',
        '-key',
        'ca.key',
        '-sha256',
        '-days',
        '1',
        '-out',
        'ca.crt',
        '-subj',
        '/CN=openpc-i07-gate3-root',
      ],
      trustRoot,
    );
    await generateIdentity(trustRoot, 'server', '127.0.0.1', 'IP:127.0.0.1');
    await generateIdentity(trustRoot, 'client', acceptedClientCommonName);
    await generateIdentity(trustRoot, 'wrong-client', 'openpc-i07-gate3-wrong-client');
    await generateIdentity(trustRoot, 'same-name-wrong-client', acceptedClientCommonName);
    await run(['genrsa', '-out', 'untrusted-client.key', '2048'], trustRoot);
    await chmod(join(trustRoot, 'untrusted-client.key'), 0o600);
    await run(
      [
        'req',
        '-x509',
        '-new',
        '-key',
        'untrusted-client.key',
        '-sha256',
        '-days',
        '1',
        '-out',
        'untrusted-client.crt',
        '-subj',
        '/CN=openpc-i07-gate3-untrusted-client',
      ],
      trustRoot,
    );
    const names = [
      'ca.crt',
      'server.crt',
      'server.key',
      'client.crt',
      'client.key',
      'wrong-client.crt',
      'wrong-client.key',
      'same-name-wrong-client.crt',
      'same-name-wrong-client.key',
      'untrusted-client.crt',
      'untrusted-client.key',
    ] as const;
    const [
      ca,
      serverCertificate,
      serverKey,
      clientCertificate,
      clientKey,
      wrongCertificate,
      wrongKey,
      sameNameWrongCertificate,
      sameNameWrongKey,
      untrustedCertificate,
      untrustedKey,
    ] = await Promise.all(names.map((name) => readFile(join(trustRoot, name))));
    if (
      !ca ||
      !serverCertificate ||
      !serverKey ||
      !clientCertificate ||
      !clientKey ||
      !wrongCertificate ||
      !wrongKey ||
      !sameNameWrongCertificate ||
      !sameNameWrongKey ||
      !untrustedCertificate ||
      !untrustedKey
    )
      throw new Error('TLS fixture material missing');
    const acceptedClientDer = Buffer.from(new X509Certificate(clientCertificate).raw);
    const exactAcceptedPeer = (socket: TLSSocket): boolean => {
      const peer = socket.getPeerCertificate(true);
      return Boolean(
        socket.authorized &&
        peer?.raw &&
        peer.raw.byteLength === acceptedClientDer.byteLength &&
        timingSafeEqual(peer.raw, acceptedClientDer),
      );
    };
    const remaining = new Map(ownedVectors.map((vector) => [vector.path, vector.maximumCalls]));
    const calls: CapturedCall[] = [];
    let startedResponses = 0;
    let completedResponses = 0;
    server = createServer(
      {
        ca,
        cert: serverCertificate,
        key: serverKey,
        minVersion: 'TLSv1.3',
        maxVersion: 'TLSv1.3',
        requestCert: true,
        rejectUnauthorized: true,
      },
      async (request, response) => {
        if (!(request.socket instanceof TLSSocket) || !exactAcceptedPeer(request.socket)) {
          request.socket.destroy();
          return;
        }
        const path = request.url ?? '';
        const vector = ownedVectors.find((candidate) => candidate.path === path);
        const budget = remaining.get(path) ?? 0;
        if (
          request.method !== 'POST' ||
          request.headers['content-type'] !== 'application/json' ||
          !vector ||
          budget < 1
        ) {
          response.writeHead(404, { 'content-type': 'application/json' });
          response.end('{}');
          return;
        }
        const chunks: Uint8Array[] = [];
        let length = 0;
        for await (const chunk of request) {
          const bytes = Buffer.from(chunk);
          length += bytes.byteLength;
          if (length > 1_048_576) {
            request.destroy();
            return;
          }
          chunks.push(bytes);
        }
        const body = Buffer.concat(chunks, length);
        const headerNames = Object.keys(request.headers).sort();
        const allowedHeaderNames = [
          'accept',
          'connection',
          'content-length',
          'content-type',
          'host',
        ];
        if (
          headerNames.some((name) => !allowedHeaderNames.includes(name)) ||
          request.headers.accept !== 'application/json' ||
          request.headers.authorization !== undefined ||
          request.headers.cookie !== undefined ||
          request.headers.host !== `127.0.0.1:${request.socket.localPort}` ||
          request.headers['content-length'] !== String(body.byteLength) ||
          body.byteLength !== vector.expectedBody.byteLength ||
          !timingSafeEqual(body, vector.expectedBody)
        ) {
          response.writeHead(400, { 'content-type': 'application/json' });
          response.end('{}');
          return;
        }
        remaining.set(path, budget - 1);
        const peer = request.socket.getPeerCertificate();
        const commonName = peer.subject?.CN;
        if (typeof commonName !== 'string') {
          request.socket.destroy();
          return;
        }
        calls.push(
          Object.freeze({
            path,
            method: request.method,
            contentType: request.headers['content-type'],
            tlsProtocol: request.socket.getProtocol() ?? '',
            clientCommonName: commonName,
            body: Uint8Array.from(body),
          }),
        );
        const headers = {
          'content-type': vector.contentType,
          ...(vector.location ? { location: vector.location } : {}),
        };
        const send = () => {
          if (response.destroyed) return;
          response.writeHead(vector.statusCode, headers);
          startedResponses += 1;
          response.end(vector.body);
          completedResponses += 1;
        };
        if (vector.responseMode === 'NEVER_SETTLE') return;
        if (vector.responseMode === 'LATE_CHUNKS') {
          response.writeHead(vector.statusCode, headers);
          startedResponses += 1;
          const split = Math.max(1, Math.floor(vector.body.byteLength / 2));
          response.write(vector.body.subarray(0, split));
          schedule(() => {
            if (!response.destroyed) {
              response.end(vector.body.subarray(split));
              completedResponses += 1;
            }
          }, vector.delayMilliseconds);
          return;
        }
        if (vector.responseMode === 'MANY_CHUNKS') {
          response.writeHead(vector.statusCode, headers);
          startedResponses += 1;
          for (let offset = 0; offset < vector.body.byteLength; offset += vector.responseChunkBytes)
            response.write(vector.body.subarray(offset, offset + vector.responseChunkBytes));
          response.end();
          completedResponses += 1;
          return;
        }
        if (vector.responseMode === 'DELAYED') schedule(send, vector.delayMilliseconds);
        else send();
      },
    );
    server.on('connection', (socket) => {
      sockets.add(socket);
      socket.once('close', () => sockets.delete(socket));
    });
    server.on('secureConnection', (socket) => {
      if (!exactAcceptedPeer(socket)) socket.destroy();
    });
    await listenOnDynamicLocalPort(server);
    const address = server.address();
    if (!address || typeof address === 'string' || address.address !== '127.0.0.1')
      throw new Error('invalid Gate 3 loopback bind');
    if (address.port < 49_152) throw new Error('failed to bind an admitted local dynamic port');
    const exposedKeys = [clientKey, wrongKey, sameNameWrongKey, untrustedKey].map(
      (key) => new Uint8Array(key),
    );
    let closed = false;
    return Object.freeze({
      origin: `https://127.0.0.1:${address.port}`,
      privateMaterialRoot: trustRoot,
      trustAnchorPem: new Uint8Array(ca),
      acceptedClientCertificatePem: new Uint8Array(clientCertificate),
      acceptedClientPrivateKeyPem: exposedKeys[0]!,
      wrongClientCertificatePem: new Uint8Array(wrongCertificate),
      wrongClientPrivateKeyPem: exposedKeys[1]!,
      sameNameWrongClientCertificatePem: new Uint8Array(sameNameWrongCertificate),
      sameNameWrongClientPrivateKeyPem: exposedKeys[2]!,
      untrustedClientCertificatePem: new Uint8Array(untrustedCertificate),
      untrustedClientPrivateKeyPem: exposedKeys[3]!,
      serverCertificatePem: new Uint8Array(serverCertificate),
      calls: () =>
        calls.map((call) => Object.freeze({ ...call, body: Uint8Array.from(call.body) })),
      startedResponseCount: () => startedResponses,
      completedResponseCount: () => completedResponses,
      pendingTimerCount: () => timers.size,
      openSocketCount: () => sockets.size,
      networkInventory: () =>
        Object.freeze({
          protocol: 'https:' as const,
          host: '127.0.0.1' as const,
          port: address.port,
          paths: Object.freeze([...admittedPaths]),
        }),
      async close() {
        if (closed) return;
        closed = true;
        for (const timer of timers) clearTimeout(timer);
        timers.clear();
        for (const socket of sockets) socket.destroy();
        sockets.clear();
        await closeServer(server!);
        for (const key of [
          ...exposedKeys,
          clientKey,
          wrongKey,
          sameNameWrongKey,
          untrustedKey,
          serverKey,
        ])
          key.fill(0);
        await rm(trustRoot, { recursive: true, force: true });
      },
    });
  } catch (error) {
    for (const timer of timers) clearTimeout(timer);
    for (const socket of sockets) socket.destroy();
    if (server) await closeServer(server).catch(() => undefined);
    await rm(trustRoot, { recursive: true, force: true });
    throw error;
  }
};
