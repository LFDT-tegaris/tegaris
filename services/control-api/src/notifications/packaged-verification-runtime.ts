import { constants } from 'node:fs';
import { open } from 'node:fs/promises';
import { createPrivateKey, X509Certificate } from 'node:crypto';
import { isIP } from 'node:net';
import { isAbsolute, normalize } from 'node:path';
import { createSecureContext } from 'node:tls';
import { z } from 'zod';
import type { NotificationCredentialProvider } from '../../../identity-service/src/domain/notification-credential-material.js';
import { canonicalJson } from '../configuration/digest.js';
import { parseStrictJsonBytes } from '../privacy-explorer/strict-json.js';
import {
  createNotificationCredentialClient,
  notificationProviderRequest,
  NotificationProviderUnavailable,
} from './credential-provider-client.js';
import { notificationChannelCredential } from './endpoint-owner-contract.js';
import {
  createNotificationVerificationRuntime,
  type NotificationVerificationRuntimeOptions,
} from './endpoint-verification-runtime.js';

const unavailable = () => new Error('Invalid notification verification configuration');
const pathSchema = z
  .string()
  .min(1)
  .max(4096)
  .refine((value) => isAbsolute(value) && normalize(value) === value && !value.includes('\0'));
const tlsFiles = z.strictObject({
  caFile: pathSchema,
  certificateFile: pathSchema,
  privateKeyFile: pathSchema,
});
const ip = z.string().refine((value) => isIP(value) !== 0);
const port = z.number().int().min(1).max(65535);
const configuration = z.strictObject({
  version: z.literal(1),
  listen: z.strictObject({ host: ip, port }),
  tls: tlsFiles,
  providers: z
    .array(
      z.strictObject({
        credential: notificationChannelCredential,
        address: ip,
        port,
        serverName: z.string().regex(/^[a-zA-Z0-9.:-]{1,253}$/u),
        serverSpkiDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
        tls: tlsFiles,
      }),
    )
    .min(1)
    .max(8),
  timeoutMs: z.number().int().min(100).max(30000).default(10000),
  connectionLifetimeMs: z.number().int().min(1000).max(300000).default(300000),
});

/** Bounded regular files only; no pipes, final symlinks or unbounded readFile.
 * Files contain transport keys/metadata, never gateway credential material. */
async function fileBytes(path: string, maximum: number): Promise<Buffer> {
  pathSchema.parse(path);
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  const bytes = Buffer.alloc(maximum + 1);
  try {
    const stat = await file.stat();
    if (!stat.isFile() || stat.size < 1 || stat.size > maximum) throw unavailable();
    let offset = 0;
    while (offset < bytes.length) {
      const read = await file.read(bytes, offset, bytes.length - offset, offset);
      if (!read.bytesRead) break;
      offset += read.bytesRead;
    }
    if (!offset || offset > maximum) throw unavailable();
    return Buffer.from(bytes.subarray(0, offset));
  } finally {
    bytes.fill(0);
    await file.close();
  }
}

type TransportTls = NotificationVerificationRuntimeOptions['tls'];
function erase(tls: TransportTls) {
  tls.ca.fill(0);
  tls.certificate.fill(0);
  tls.privateKey.fill(0);
}
async function transportTls(
  files: z.infer<typeof tlsFiles>,
  kind: 'server' | 'client',
  participantId?: string,
): Promise<TransportTls> {
  const buffers: Buffer[] = [];
  try {
    // Sequential reads keep every owned buffer reachable if a later read fails.
    for (const path of [files.caFile, files.certificateFile, files.privateKeyFile])
      buffers.push(await fileBytes(path, 65536));
    const [ca, certificate, privateKey] = buffers as [Buffer, Buffer, Buffer];
    const parsed = new X509Certificate(certificate);
    if (
      !new X509Certificate(ca).ca ||
      parsed.ca ||
      !parsed.checkPrivateKey(createPrivateKey(privateKey)) ||
      !parsed.keyUsage?.includes(kind === 'server' ? '1.3.6.1.5.5.7.3.1' : '1.3.6.1.5.5.7.3.2')
    )
      throw unavailable();
    if (kind === 'client') {
      const sans = parsed.subjectAltName?.split(', ').filter((san) => san.startsWith('URI:'));
      if (
        sans?.length !== 1 ||
        !new RegExp(
          `^URI:urn:openpc:participant:${participantId}:workload:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`,
          'u',
        ).test(sans[0]!)
      )
        throw unavailable();
    }
    createSecureContext({
      ca,
      cert: certificate,
      key: privateKey,
      minVersion: 'TLSv1.3',
      maxVersion: 'TLSv1.3',
    });
    return { ca, certificate, privateKey };
  } catch {
    for (const bytes of buffers) bytes.fill(0);
    throw unavailable();
  }
}

export type PackagedNotificationVerificationOptions = Pick<
  NotificationVerificationRuntimeOptions,
  'identityRuntimeVerifier' | 'businessEvidence'
> & {
  readonly database: {
    readonly host: string;
    readonly port: number;
    readonly database: string;
    readonly user: string;
    readonly password: string;
  };
};

/** Optional packaged root. It creates transport clients, never physical providers
 * or installation authority. The existing runtime authenticates the live peer,
 * current installed binding and Identity recipient around each provider borrow.
 * Configuration alone neither exports material nor establishes VERIFY readiness.
 * Returned workflow is exposed only after its inbound listener has started. */
export async function loadPackagedNotificationVerificationRuntime(
  path: string | undefined,
  options: PackagedNotificationVerificationOptions,
) {
  if (path === undefined) return undefined;
  const clients = new Map<string, ReturnType<typeof createNotificationCredentialClient>>();
  let runtime: ReturnType<typeof createNotificationVerificationRuntime> | undefined;
  let listenerTls: TransportTls | undefined;
  let closing: Promise<void> | undefined;
  let closed = false;
  const close = () => {
    closed = true;
    closing ??= (async () => {
      let failed = false;
      // Initiate listener/borrow shutdown before invalidating client leases. Local
      // close never reports remote drain/erasure or reconciles an UNKNOWN effect.
      const stopped = (async () => {
        try {
          await runtime?.close();
        } catch {
          failed = true;
        }
      })();
      for (const client of clients.values()) {
        try {
          client.close();
        } catch {
          failed = true;
        }
      }
      await stopped;
      if (listenerTls) erase(listenerTls);
      if (failed) throw new Error('Notification packaged runtime cleanup failed');
    })();
    return closing;
  };
  try {
    const bytes = await fileBytes(path, 262144);
    let config: z.infer<typeof configuration>;
    try {
      config = configuration.parse(parseStrictJsonBytes(bytes, { maximumDepth: 8 }));
    } finally {
      bytes.fill(0);
    }
    // The root reuses the packaged runtime login, never an installation/owner URL.
    const database = z
      .strictObject({
        host: z.string().min(1),
        port,
        database: z.string().min(1),
        user: z.literal('openpc_configuration_runtime'),
        password: z.string().min(1),
      })
      .parse(options.database);
    const references = new Set<string>();
    for (const entry of config.providers) {
      const credential = entry.credential;
      const reference = canonicalJson([
        credential.participantId,
        credential.privacyDomainId,
        credential.credentialRef,
      ]);
      if (references.has(reference)) throw unavailable();
      references.add(reference);
    }
    listenerTls = await transportTls(config.tls, 'server');
    for (const entry of config.providers) {
      const tls = await transportTls(entry.tls, 'client', entry.credential.participantId);
      try {
        const { participantId, privacyDomainId, credentialRef, reference, version, epoch } =
          entry.credential;
        const key = canonicalJson(
          notificationProviderRequest.parse({
            participantId,
            privacyDomainId,
            credentialRef,
            reference,
            version,
            epoch,
            purpose: 'NOTIFICATION_GATEWAY_CREDENTIAL',
            consumer: 'LS-NOTIFICATION',
          }),
        );
        clients.set(
          key,
          createNotificationCredentialClient({
            ...entry,
            tls,
            timeoutMs: config.timeoutMs,
          }),
        );
      } finally {
        erase(tls);
      }
    }
    const credentialProvider: NotificationCredentialProvider = {
      async withExactVersion(request, use) {
        const parsed = notificationProviderRequest.safeParse(request);
        if (closed || !parsed.success) throw new NotificationProviderUnavailable();
        const client = clients.get(canonicalJson(parsed.data));
        if (!client) throw new NotificationProviderUnavailable();
        return client.withExactVersion(request, use);
      },
    };
    runtime = createNotificationVerificationRuntime({
      database,
      tls: listenerTls,
      credentialProvider,
      identityRuntimeVerifier: options.identityRuntimeVerifier,
      businessEvidence: options.businessEvidence,
      timeoutMs: config.timeoutMs,
      connectionLifetimeMs: config.connectionLifetimeMs,
    });
    await runtime.start(config.listen);
    const owned = runtime;
    return Object.freeze({
      workflow: owned.workflow,
      owners: owned.owners,
      preflight: owned.preflight,
      close,
    });
  } catch {
    // Cleanup rejection takes precedence as an unresolved local resource failure;
    // neither error includes paths, credentials, frames or provider diagnostics.
    await close();
    throw unavailable();
  }
}

// Shared mounted-transport owner; aliases preserve the existing validation and
// erasure behavior for the separate, unwired delivery composition.
export { fileBytes as readNotificationTransportFile, transportTls as readNotificationTransportTls };
export type { TransportTls as NotificationTransportTls };
