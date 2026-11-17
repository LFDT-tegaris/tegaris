import { runtimeArtifactArchiveRequest } from './runtime-artifact-archive-source.js';
import { constants } from 'node:fs';
import { open, readFile } from 'node:fs/promises';
import { isAbsolute } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { Pool } from 'pg';
import { z } from 'zod';
import { EvidenceCustody } from './custody.js';
import { EvidenceExportWorker } from './export-worker.js';
import { LocalEvidenceVault } from './local-vault.js';
import { evidenceScope, EvidenceCustodyError } from './segment.js';
import { factEvidenceSource } from './fact-source.js';
import { rpcEvidenceSource } from './rpc-source.js';
import { candidateArchiveSource } from './candidate-archive/source.js';
import { candidateArchiveRequest } from './candidate-archive/contract.js';
import { archiveProtectedProof, protectedCustodyScope } from './protected-custody.js';
import { LocalProtectedProofVault } from './protected-vault.js';
import {
  openStoreRetirementRuntime,
  storeRetirementRuntimeConfiguration,
} from './store-retirement-runtime.js';
import {
  openRemoteArchiveRuntime,
  remoteArchiveRuntimeConfiguration,
} from './remote-archive-runtime.js';

const absolutePath = z.string().refine(isAbsolute);
const configuration = z.strictObject({
  database: z.strictObject({
    host: z.string().min(1),
    port: z.number().int().min(1).max(65535),
    database: z.string().min(1),
    user: z.string().min(1),
    passwordFile: absolutePath,
  }),
  vaultDirectory: absolutePath,
  sinkId: z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9:._-]{0,159}$/u),
  pollIntervalMs: z.number().int().min(100).max(60000).default(1000),
  protectedScopes: z.array(protectedCustodyScope).max(1024).default([]),
  remoteArchives: z.array(remoteArchiveRuntimeConfiguration).max(64).default([]),
  storeRetirements: z.array(storeRetirementRuntimeConfiguration).max(16).default([]),
  scopes: z
    .array(
      evidenceScope
        .extend({
          source: z
            .enum([
              'BUSINESS_TRANSITION',
              'AUTHENTICATION',
              'EFFECT',
              'RPC',
              'FACT',
              'FACT_FAILURE',
              'NOTIFICATION_OUTCOME',
              'CANDIDATE',
              'RUNTIME_ARTIFACT',
            ])
            .default('BUSINESS_TRANSITION'),
          exportSinkId: z
            .string()
            .regex(/^[a-zA-Z0-9][a-zA-Z0-9:._-]{0,159}$/u)
            .optional(),
          activeKeyId: z.string().min(1).max(160),
          keys: z
            .array(z.strictObject({ keyId: z.string().min(1).max(160), keyFile: absolutePath }))
            .min(1)
            .max(64),
          retentionSeconds: z.number().int().min(60).max(315360000),
          capacityBytes: z.number().int().min(1024).max(1073741824),
          rpc: rpcEvidenceSource.optional(),
          fact: factEvidenceSource.optional(),
          runtimeArtifact: runtimeArtifactArchiveRequest.optional(),
          candidate: z
            .strictObject({ source: candidateArchiveSource, request: candidateArchiveRequest })
            .optional(),
        })
        .refine(
          (scope) =>
            (scope.source === 'RUNTIME_ARTIFACT') === (scope.runtimeArtifact !== undefined) &&
            (!scope.runtimeArtifact ||
              (scope.runtimeArtifact.participantId === scope.participantId &&
                scope.runtimeArtifact.privacyDomainId === scope.privacyDomainId)) &&
            (scope.source === 'RPC') === (scope.rpc !== undefined) &&
            (scope.source === 'FACT') === (scope.fact !== undefined) &&
            (scope.source === 'CANDIDATE') === (scope.candidate !== undefined) &&
            (!scope.candidate ||
              (scope.candidate.source.participantId === scope.participantId &&
                scope.candidate.source.privacyDomainId === scope.privacyDomainId &&
                scope.candidate.request.participantId === scope.participantId &&
                scope.candidate.request.privacyDomainId === scope.privacyDomainId &&
                scope.candidate.request.sourceProfileId ===
                  scope.candidate.source.sourceProfileId)),
        ),
    )
    .min(1)
    .max(1024),
});

async function readKey(path: string) {
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const stat = await file.stat();
    if (!stat.isFile() || stat.size !== 32 || (stat.mode & 0o077) !== 0)
      throw new Error('invalid evidence key');
    const key = await file.readFile();
    if (key.length !== 32) throw new Error('invalid evidence key');
    return key;
  } finally {
    await file.close();
  }
}

/** Dedicated service executable: only its own worker database login and mounted
 * encryption keys are loaded here. Public HTTP handlers never receive this pool.
 * Configuration is host-owned; no request can select scopes, keys or retention.
 */
async function main() {
  const args = process.argv.slice(2);
  if (args.length > 1 || (args[0] !== undefined && args[0] !== '--once'))
    throw new Error('invalid worker argument');
  const path = absolutePath.parse(process.env.OPENPC_EVIDENCE_WORKER_CONFIG_FILE);
  const config = configuration.parse(JSON.parse(await readFile(path, 'utf8')));
  const password = (await readFile(config.database.passwordFile, 'utf8')).trim();
  if (password.length < 32 || password.length > 256 || !/^\S+$/u.test(password))
    throw new Error('invalid worker secret');
  const sink = await LocalEvidenceVault.open(config.vaultDirectory, config.sinkId);
  const protectedSink = await LocalProtectedProofVault.open(config.vaultDirectory, config.sinkId);
  if (
    new Set(
      config.protectedScopes.map((scope) => `${scope.participantId}:${scope.privacyDomainId}`),
    ).size !== config.protectedScopes.length
  )
    throw new Error('duplicate protected custody scope');
  const pool = new Pool({
    host: config.database.host,
    port: config.database.port,
    database: config.database.database,
    user: config.database.user,
    password,
    max: 2,
    connectionTimeoutMillis: 5000,
    statement_timeout: 30000,
  });
  const stopping = new AbortController();
  const stop = () => stopping.abort();
  process.once('SIGTERM', stop);
  process.once('SIGINT', stop);
  const keySets = new Map<string, Map<string, Buffer>>();
  const remoteArchives: Awaited<ReturnType<typeof openRemoteArchiveRuntime>>[] = [];
  const storeRetirements: Awaited<ReturnType<typeof openStoreRetirementRuntime>>[] = [];
  const scopeKey = (scope: z.infer<typeof evidenceScope>) =>
    JSON.stringify([scope.participantId, scope.privacyDomainId, scope.streamId]);
  try {
    for (const retirement of config.storeRetirements) {
      const runtime = await openStoreRetirementRuntime(pool, retirement);
      if (storeRetirements.some((item) => item.hostDigest === runtime.hostDigest)) {
        runtime.close();
        throw new Error('Duplicate retirement host');
      }
      storeRetirements.push(runtime);
    }
    for (const entry of config.scopes) {
      const key = scopeKey(entry);
      if (keySets.has(key)) throw new Error('duplicate evidence scope');
      const keys = new Map<string, Buffer>();
      keySets.set(key, keys);
      for (const item of entry.keys) {
        if (keys.has(item.keyId)) throw new Error('duplicate evidence key');
        keys.set(item.keyId, await readKey(item.keyFile));
      }
      if (!keys.has(entry.activeKeyId)) throw new Error('missing active evidence key');
    }
    for (const remote of config.remoteArchives) {
      if (
        remote.trust.sinkId === config.sinkId ||
        remoteArchives.some(
          (existing) =>
            existing.sinkId === remote.trust.sinkId &&
            existing.scopes.some(
              (s) =>
                s.participantId === remote.trust.participantId &&
                s.privacyDomainId === remote.trust.privacyDomainId,
            ),
        )
      )
        throw new Error('duplicate archive sink authority');
      remoteArchives.push(await openRemoteArchiveRuntime(pool, remote, config.scopes));
    }
    const custody = new EvidenceCustody(pool);
    const exporters = new Map<string, EvidenceExportWorker>();
    for (const entry of config.scopes) {
      const chosen = entry.exportSinkId ?? config.sinkId;
      const remote = remoteArchives.find(
        (item) =>
          item.sinkId === chosen && item.scopes.some((s) => scopeKey(s) === scopeKey(entry)),
      );
      if (chosen !== config.sinkId && !remote?.reader)
        throw new Error('missing export sink authority');
      exporters.set(
        scopeKey(entry),
        new EvidenceExportWorker(pool, remote?.reader ?? sink, async (scope, keyId) => {
          const key = keySets.get(scopeKey(scope))?.get(keyId);
          if (!key) throw new EvidenceCustodyError('UNAVAILABLE');
          return key;
        }),
      );
    }
    let failed = false;
    do {
      for (const entry of config.scopes) {
        if (stopping.signal.aborted) break;
        const scope = {
          participantId: entry.participantId,
          privacyDomainId: entry.privacyDomainId,
          streamId: entry.streamId,
        };
        const retentionUntil = new Date(Date.now() + entry.retentionSeconds * 1000)
          .toISOString()
          .replace(/\.(\d{3})Z$/u, '.$1000Z');
        const encryption = {
          keyId: entry.activeKeyId,
          key: keySets.get(scopeKey(scope))!.get(entry.activeKeyId)!,
        };
        const ingest = () => {
          if (entry.source === 'RUNTIME_ARTIFACT')
            return custody.ingestRuntimeArtifact(
              scope,
              entry.runtimeArtifact!,
              encryption,
              retentionUntil,
              entry.capacityBytes,
              async (keyId) => {
                const key = keySets.get(scopeKey(scope))?.get(keyId);
                if (!key) throw new EvidenceCustodyError('UNAVAILABLE');
                return key;
              },
            );
          if (entry.source === 'CANDIDATE')
            return custody.ingestCandidate(
              scope,
              entry.candidate!.source,
              entry.candidate!.request,
              encryption,
              retentionUntil,
              entry.capacityBytes,
              async (keyId) => {
                const key = keySets.get(scopeKey(scope))?.get(keyId);
                if (!key) throw new EvidenceCustodyError('UNAVAILABLE');
                return key;
              },
            );
          if (entry.source === 'RPC')
            return custody.ingestRpc(
              scope,
              entry.rpc!,
              encryption,
              retentionUntil,
              entry.capacityBytes,
            );
          if (entry.source === 'FACT')
            return custody.ingestFact(
              scope,
              entry.fact!,
              encryption,
              retentionUntil,
              entry.capacityBytes,
            );
          const method = {
            BUSINESS_TRANSITION: 'ingestBusiness',
            AUTHENTICATION: 'ingestAuthentication',
            EFFECT: 'ingestEffect',
            FACT_FAILURE: 'ingestFactFailure',
            NOTIFICATION_OUTCOME: 'ingestNotificationOutcomes',
          } as const;
          return custody[method[entry.source]](
            scope,
            encryption,
            retentionUntil,
            entry.capacityBytes,
          );
        };
        const phases = [
          ['ingest', ingest],
          ['archive', () => custody.exportNext(scope, sink)],
          ['holds', () => custody.reconcileHolds(scope, sink)],
          ['export', () => exporters.get(scopeKey(scope))!.runNext(scope)],
        ] as const;
        // A blocked new admission must not prevent previously admitted data
        // from reaching its sink or an already-approved export from completing.
        for (const [phase, run] of phases)
          try {
            await run();
          } catch (error) {
            failed = true;
            // No scope identities, receipt bytes, keys, SQL or environment appear in logs.
            process.stderr.write(
              JSON.stringify({
                event: 'evidence_worker_retry',
                phase,
                code: error instanceof EvidenceCustodyError ? error.code : 'UNAVAILABLE',
              }) + '\n',
            );
          }
        for (const remote of remoteArchives) {
          if (stopping.signal.aborted) break;
          if (!remote.scopes.some((s) => scopeKey(s) === scopeKey(scope))) continue;
          const archive = remote.forScope(scope);
          for (const [phase, run] of [
            ['remote-archive', () => archive.exportNext(stopping.signal)],
            ['remote-holds', () => archive.reconcileHolds(stopping.signal)],
          ] as const) {
            if (stopping.signal.aborted) break;
            try {
              await run();
            } catch {
              failed = true;
              process.stderr.write(
                JSON.stringify({ event: 'evidence_worker_retry', phase, code: 'UNAVAILABLE' }) +
                  '\n',
              );
            }
          }
        }
      }
      for (const scope of config.protectedScopes) {
        if (stopping.signal.aborted) break;
        try {
          await archiveProtectedProof(pool, scope, protectedSink);
        } catch (error) {
          failed = true;
          process.stderr.write(
            JSON.stringify({
              event: 'evidence_worker_retry',
              phase: 'protected-archive',
              code: error instanceof EvidenceCustodyError ? error.code : 'UNAVAILABLE',
            }) + '\n',
          );
        }
      }
      for (const retirement of storeRetirements) {
        if (stopping.signal.aborted) break;
        try {
          await retirement.runPending(stopping.signal);
        } catch {
          failed = true;
          process.stderr.write(
            JSON.stringify({
              event: 'evidence_worker_retry',
              phase: 'store-retirement',
              code: 'UNAVAILABLE',
            }) + '\n',
          );
        }
      }
      if (args[0] === '--once') break;
      await delay(config.pollIntervalMs, undefined, { signal: stopping.signal }).catch(
        () => undefined,
      );
    } while (!stopping.signal.aborted);
    if (failed && args[0] === '--once') process.exitCode = 1;
  } finally {
    stopping.abort();
    for (const keys of keySets.values()) for (const key of keys.values()) key.fill(0);
    for (const remote of remoteArchives) remote.close();
    for (const retirement of storeRetirements) retirement.close();
    await pool.end();
    process.removeListener('SIGTERM', stop);
    process.removeListener('SIGINT', stop);
  }
}

void main().catch(() => {
  process.stderr.write('{"event":"evidence_worker_stopped","code":"UNAVAILABLE"}\n');
  process.exitCode = 1;
});
