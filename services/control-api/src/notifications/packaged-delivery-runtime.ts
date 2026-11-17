import { X509Certificate } from 'node:crypto';
import { access } from 'node:fs/promises';
import { constants } from 'node:fs';
import { openVaultDirectory } from '../evidence/immutable-vault.js';
import type { PoolConfig } from 'pg';
import {
  NotificationDeliveryConsumerRuntime,
  notificationConsumerMount,
} from './delivery-consumer-runtime.js';
import { isAbsolute, normalize } from 'node:path';
import { isIP } from 'node:net';
import { z } from 'zod';
import { canonicalJson } from '../configuration/digest.js';
import { parseStrictJsonBytes } from '../privacy-explorer/strict-json.js';
import type { NotificationCredentialProvider } from '../../../identity-service/src/domain/notification-credential-material.js';
import { notificationChannelCredential } from './endpoint-owner-contract.js';
import { notificationWorkerSelector } from './worker-installation.js';
import { notificationDeliverySourceSelector } from './delivery-source.js';
import {
  createNotificationCredentialClient,
  notificationProviderRequest,
  NotificationProviderUnavailable,
} from './credential-provider-client.js';
import {
  readNotificationTransportFile,
  readNotificationTransportTls,
  type NotificationTransportTls,
} from './packaged-verification-runtime.js';
import {
  NotificationDeliveryRuntime,
  type NotificationDeliveryRuntimeOptions,
  type NotificationDeliveryPeers,
} from './delivery-runtime.js';

const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const path = z
  .string()
  .min(1)
  .max(4096)
  .refine((p) => isAbsolute(p) && normalize(p) === p && !p.includes('\0'));
const files = z.strictObject({ caFile: path, certificateFile: path, privateKeyFile: path });
const configuration = z.strictObject({
  version: z.literal(1),
  worker: notificationWorkerSelector,
  vaultDirectory: path,
  kmsTls: files,
  signerTls: files,
  signers: z.strictObject({ start: digest, outcome: digest }),
  // Explicit transport time budget only; never an async lease/capacity default.
  timeoutMs: z.number().int().min(100).max(10000),
  providers: z
    .array(
      z.strictObject({
        credential: notificationChannelCredential,
        address: z.string().refine((v) => isIP(v) !== 0),
        port: z.number().int().min(1).max(65535),
        serverName: z.string().regex(/^[a-zA-Z0-9.:-]{1,253}$/u),
        serverSpkiDigest: digest,
        tls: files,
      }),
    )
    .min(1)
    .max(8),
});
const servingConfiguration = configuration.extend({
  version: z.literal(2),
  cancellationSignerInstallationDigest: digest,
  consumer: notificationConsumerMount.extend({
    listenerTls: files,
    workerTls: files,
    recipientTls: files,
  }),
});
/** Shared strict mounting parser. Parsing cannot create serving authority. */
export function parseNotificationDeliveryServingConfiguration(value: unknown) {
  return servingConfiguration.parse(value);
}
export type PackagedNotificationDeliveryOptions = Pick<
  NotificationDeliveryRuntimeOptions,
  'pool' | 'kernel'
>;
const invalid = () => new Error('Notification delivery package unavailable');
function erase(tls: NotificationTransportTls) {
  for (const bytes of [tls.ca, tls.certificate, tls.privateKey]) bytes.fill(0);
}
/** Loads strict mounted transport configuration only. No listener, Pool, provider
 * fixture, worker polling, installation, async qualification or startup grant.
 * The canonical root stays UNWIRED until its real async/current consumer owner
 * and same-environment EFFECTIVE generation are available. */
async function loadPackage(
  file: string | undefined,
  options: PackagedNotificationDeliveryOptions | { database: PoolConfig },
  serving: boolean,
) {
  if (file === undefined) return undefined;
  const clients = new Map<string, ReturnType<typeof createNotificationCredentialClient>>();
  const held = new Set<Promise<unknown>>();
  const materials: NotificationTransportTls[] = [];
  let runtime: NotificationDeliveryRuntime | undefined;
  let consumer: NotificationDeliveryConsumerRuntime | undefined;
  let closed = false;
  let closing: Promise<void> | undefined;
  const close = () => {
    if (closing) return closing;
    closed = true;
    // Stop all transports immediately, then await the actual owners/callbacks.
    const stopped = consumer ? consumer.close() : runtime?.close();
    const errors: unknown[] = [];
    const drain = Promise.resolve(stopped).catch((error) => {
      errors.push(error);
    });
    for (const client of clients.values()) {
      try {
        client.close();
      } catch (error) {
        errors.push(error);
      }
    }
    closing = (async () => {
      await drain;
      const callbacks = await Promise.allSettled([...held]);
      for (const result of callbacks) if (result.status === 'rejected') errors.push(result.reason);
      for (const tls of materials) erase(tls);
      clients.clear();
      if (errors.length)
        throw new AggregateError(errors, 'Notification delivery package drain failed');
    })();
    return closing;
  };
  try {
    const bytes = await readNotificationTransportFile(file, 262144);
    let config: z.infer<typeof configuration> | z.infer<typeof servingConfiguration>;
    try {
      config = (serving ? servingConfiguration : configuration).parse(
        parseStrictJsonBytes(bytes, { maximumDepth: 8 }),
      );
    } finally {
      bytes.fill(0);
    }
    const scope = config.worker;
    const credentialKeys = new Set<string>();
    for (const entry of config.providers) {
      if (
        entry.credential.participantId !== scope.participantId ||
        entry.credential.privacyDomainId !== scope.privacyDomainId
      )
        throw invalid();
      const key = canonicalJson([
        entry.credential.participantId,
        entry.credential.privacyDomainId,
        entry.credential.credentialRef,
      ]);
      if (credentialKeys.has(key)) throw invalid();
      credentialKeys.add(key);
    }
    const kmsTls = await readNotificationTransportTls(config.kmsTls, 'client', scope.participantId);
    materials.push(kmsTls);
    const signerTls = await readNotificationTransportTls(
      config.signerTls,
      'client',
      scope.participantId,
    );
    materials.push(signerTls);
    for (const entry of config.providers) {
      const tls = await readNotificationTransportTls(entry.tls, 'client', scope.participantId);
      materials.push(tls);
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
        createNotificationCredentialClient({ ...entry, tls, timeoutMs: config.timeoutMs }),
      );
    }
    const credentialProvider: NotificationCredentialProvider = {
      async withExactVersion(request, use) {
        const parsed = notificationProviderRequest.safeParse(request);
        if (closed || !parsed.success) throw new NotificationProviderUnavailable();
        const client = clients.get(canonicalJson(parsed.data));
        if (!client) throw new NotificationProviderUnavailable();
        let callback: Promise<unknown> | undefined;
        try {
          return await client.withExactVersion(request, (material) => {
            if (closed) throw new NotificationProviderUnavailable();
            const pending = Promise.resolve().then(() => {
              if (closed) throw new NotificationProviderUnavailable();
              return use(material);
            });
            callback = pending;
            held.add(pending);
            void pending.then(
              () => held.delete(pending),
              () => held.delete(pending),
            );
            return pending;
          });
        } finally {
          // The external client may lose its connection before a callback that
          // ignored abort finishes. Keep the local SQL/recipient owner held.
          if (callback) await Promise.allSettled([callback]);
        }
      },
    };
    const common = {
      credentialProvider,
      vaultDirectory: config.vaultDirectory,
      kmsTls,
      signerTls: {
        trustCa: signerTls.ca,
        certificate: signerTls.certificate,
        privateKey: signerTls.privateKey,
        timeoutMs: config.timeoutMs,
      },
      signers: config.signers,
    };
    if (config.version === 2) {
      // Check the actual runtime user against the pre-existing read-only vault;
      // mounting a path is not filesystem or payload authority.
      await access(config.vaultDirectory, constants.R_OK | constants.X_OK);
      await openVaultDirectory(config.vaultDirectory);
      if (!('database' in options)) throw invalid();
      const listenerTls = await readNotificationTransportTls(config.consumer.listenerTls, 'server');
      materials.push(listenerTls);
      const server = new X509Certificate(listenerTls.certificate);
      if (
        !(isIP(config.consumer.serverName)
          ? server.checkIP(config.consumer.serverName)
          : server.checkHost(config.consumer.serverName))
      )
        throw invalid();
      const workerTls = await readNotificationTransportTls(
        config.consumer.workerTls,
        'client',
        scope.participantId,
      );
      materials.push(workerTls);
      const recipientTls = await readNotificationTransportTls(
        config.consumer.recipientTls,
        'client',
        scope.participantId,
      );
      materials.push(recipientTls);
      const mount = notificationConsumerMount.parse({
        listen: config.consumer.listen,
        serverName: config.consumer.serverName,
        unavailableRetryMs: config.consumer.unavailableRetryMs,
        ceilings: config.consumer.ceilings,
      });
      consumer = new NotificationDeliveryConsumerRuntime({
        ...common,
        database: options.database,
        worker: scope,
        mount,
        listenerTls,
        workerTls,
        recipientTls,
        cancellationSignerInstallationDigest: config.cancellationSignerInstallationDigest,
      });
      const owned = consumer;
      return Object.freeze({
        kind: 'consumer' as const,
        start: () => owned.start(),
        status: () => owned.status(),
        close,
      });
    }
    if (!('pool' in options)) throw invalid();
    runtime = new NotificationDeliveryRuntime({ ...common, ...options });
    const owned = runtime;
    const source = (value: unknown) => {
      if (closed) throw invalid();
      const selected = notificationDeliverySourceSelector.parse(value);
      if (canonicalJson(selected.worker) !== canonicalJson(scope)) throw invalid();
      return selected;
    };
    return Object.freeze({
      kind: 'manual' as const,
      packagingStatus: owned.packagingStatus,
      start(peers: NotificationDeliveryPeers, value: unknown) {
        return owned.start(peers, source(value));
      },
      lookup(
        peers: NotificationDeliveryPeers,
        value: Parameters<NotificationDeliveryRuntime['lookup']>[1],
      ) {
        if (!value || typeof value !== 'object' || !('source' in value)) throw invalid();
        source(value.source);
        return owned.lookup(peers, value);
      },
      close,
    });
  } catch (primary) {
    try {
      await close();
    } catch (cleanup) {
      throw new AggregateError(
        [primary, cleanup],
        'Notification delivery package setup and cleanup failed',
      );
    }
    throw invalid();
  }
}

/** Compatibility-only manual v1 composition. Never mounted as the serving worker. */
export async function loadPackagedNotificationDeliveryRuntime(
  file: string | undefined,
  options: PackagedNotificationDeliveryOptions,
) {
  const loaded = await loadPackage(file, options, false);
  if (!loaded) return undefined;
  if (loaded.kind !== 'manual') {
    await loaded.close();
    throw invalid();
  }
  return Object.freeze({
    packagingStatus: loaded.packagingStatus,
    start: loaded.start,
    lookup: loaded.lookup,
    close: loaded.close,
  });
}
/** The serving v2 facade accepts no peer, source, readiness or native DTO. */
export async function loadPackagedNotificationDeliveryConsumer(
  file: string | undefined,
  options: { database: PoolConfig },
) {
  const loaded = await loadPackage(file, options, true);
  if (!loaded) return undefined;
  if (loaded.kind !== 'consumer') {
    await loaded.close();
    throw invalid();
  }
  return Object.freeze({ start: loaded.start, status: loaded.status, close: loaded.close });
}
