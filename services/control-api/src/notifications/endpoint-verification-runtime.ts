import { Pool, type PoolConfig } from 'pg';
import {
  IdentityKernel,
  PostgresIdentityRepository,
  systemClock,
} from '../../../identity-service/src/domain/identity-kernel.js';
import type { IdentityRuntimeVerifier } from '../../../identity-service/src/domain/identity-runtime-crypto.js';
import type { NotificationCredentialProvider } from '../../../identity-service/src/domain/notification-credential-material.js';
import {
  NotificationWorkloadTransport,
  type NotificationWorkloadTransportOptions,
} from '../../../identity-service/src/domain/notification-workload-transport.js';
import type { ConfigurationBusinessEvidence } from '../configuration/persistence/business-receipt-writer.js';
import { NotificationEndpointVerificationWorkflow } from './endpoint-verification-workflow.js';
import type { NotificationChannelCredential } from './endpoint-owner-contract.js';
import { NotificationEndpointVerificationState } from './endpoint-verification-state.js';

export interface NotificationVerificationRuntimeOptions {
  /** Runtime role only. Installation/owner credentials never enter this leaf. */
  readonly database: PoolConfig;
  readonly tls: NotificationWorkloadTransportOptions['tls'];
  readonly identityRuntimeVerifier: IdentityRuntimeVerifier;
  readonly businessEvidence: ConfigurationBusinessEvidence;
  /** Root-owned concrete physical provider. No material path/env/cache fallback,
   * restoration or inferred eligibility is supplied by this composition leaf. */
  readonly credentialProvider: NotificationCredentialProvider;
  readonly timeoutMs?: number;
  readonly connectionLifetimeMs?: number;
}

/** Trusted root composition. Three capped persistent connections total: two for
 * metadata/transport and one for the live recipient fence. Atomic mutation's
 * existing business connection remains separately owned and admitted. Nothing
 * listens, authenticates or connects to PostgreSQL until the root starts/uses it.
 * Missing peers close VERIFY while public metadata remains independently usable. */
export function createNotificationVerificationRuntime(
  options: NotificationVerificationRuntimeOptions,
) {
  const bounded = {
    ...options.database,
    connectionTimeoutMillis: 5000,
    statement_timeout: 5000,
    idle_in_transaction_session_timeout: 30000,
    idleTimeoutMillis: 10000,
  };
  const pool = new Pool({ ...bounded, max: 2 });
  const recipientPool = new Pool({ ...bounded, max: 1 });
  let transport: NotificationWorkloadTransport | undefined;
  let workflow: NotificationEndpointVerificationWorkflow;
  let owners: NotificationEndpointVerificationState;
  try {
    const kernel = new IdentityKernel(new PostgresIdentityRepository(recipientPool, systemClock));
    transport = new NotificationWorkloadTransport({
      pool,
      kernel,
      tls: options.tls,
      ...(options.connectionLifetimeMs === undefined
        ? {}
        : { connectionLifetimeMs: options.connectionLifetimeMs }),
    });
    workflow = new NotificationEndpointVerificationWorkflow({
      pool,
      recipientPool,
      kernel,
      identityRuntimeVerifier: options.identityRuntimeVerifier,
      businessEvidence: options.businessEvidence,
      workloadPeer: transport,
      credentialProvider: options.credentialProvider,
      timeoutMs: options.timeoutMs ?? 10000,
    });
    owners = new NotificationEndpointVerificationState(pool, options.identityRuntimeVerifier);
  } catch (error) {
    // No pool has connected yet. Still close both on rejected root configuration.
    void transport?.close().catch(() => {});
    void pool.end().catch(() => {});
    void recipientPool.end().catch(() => {});
    throw error;
  }
  if (!transport) throw new Error('Notification runtime composition failed');
  const ownedTransport = transport;
  let closing: Promise<void> | undefined;
  return Object.freeze({
    workflow,
    owners,
    // Connected transport preflight only; this neither exports material nor
    // replaces the real recipient and final authority checks in VERIFY.
    preflight: (credential: NotificationChannelCredential) =>
      ownedTransport.withPeer(credential, async () => {}),
    start: (listen: { host: string; port: number }) => ownedTransport.listen(listen),
    close() {
      closing ??= (async () => {
        let transportError: unknown;
        try {
          await ownedTransport.close();
        } catch (error) {
          transportError = error;
        }
        const result = await Promise.allSettled([pool.end(), recipientPool.end()]);
        if (transportError || result.some((item) => item.status === 'rejected'))
          throw new Error('Notification runtime cleanup failed');
      })();
      return closing;
    },
  });
}
