import { inspectNotificationPreEffectResume } from './async-worker-state.js';
import { publishNotificationDeliveryOutcomeLeased } from './delivery-outcome-publication.js';
import { prepareNotificationOutcomeSigningLeased } from './delivery-outcome-state.js';
import { withNotificationDeliveryMaterialContextLeased } from './delivery-material-context.js';
import { claimNotificationDeliveryDispatchLeased } from './delivery-dispatch-state.js';
import { publishNotificationDeliveryStartLeased } from './delivery-start-atomic.js';
import { prepareNotificationDeliverySigningLeased } from './delivery-signing-state.js';
import { synchronizeNotificationDeliveryBudgetLeased } from './delivery-start-state.js';
import { prepareNotificationDeliveryLeased } from './delivery-start-preparation.js';
import {
  notificationWorkerLeaseSelector,
  notificationWorkerLeaseSignal,
  type NotificationWorkerLeaseSelector,
} from './async-worker-state.js';
import { prepareNotificationRetryDeliveryLeased } from './delivery-start-preparation.js';
import type { NotificationOutcomeSigningSelector } from './delivery-outcome-state.js';
import { Pool } from 'pg';
import { TLSSocket } from 'node:tls';
import { z } from 'zod';
import { IdentityKernel } from '../../../identity-service/src/domain/identity-kernel.js';
import type { NotificationCredentialProvider } from '../../../identity-service/src/domain/notification-credential-material.js';
import { withNotificationSecretRecipient } from '../../../identity-service/src/domain/notification-secret-recipient.js';
import { immutableJsonCopy } from '../privacy-explorer/immutable.js';
import { canonicalJson } from '../configuration/digest.js';
import { EvidenceKmsRuntime, type EvidenceKmsTlsMaterial } from '../evidence/kms-runtime.js';
import { NotificationPayloadReferenceGate } from './payload-reference.js';
import { NotificationDeliveryMaterial } from './delivery-material.js';
import { notificationDeliverySourceSelector } from './delivery-source.js';
import {
  withNotificationDeliveryRequest,
  withNotificationDeliveryConfiguration,
} from './delivery-admission.js';
import {
  prepareNotificationDelivery,
  readNotificationDeliveryPreparation,
} from './delivery-start-preparation.js';
import { synchronizeNotificationDeliveryBudget } from './delivery-start-state.js';
import { notificationDeliverySigningSelector } from './delivery-signing-contract.js';
import {
  prepareNotificationDeliverySigning,
  withNotificationSigningHistory,
} from './delivery-signing-state.js';
import { NotificationDeliverySigningRuntime } from './delivery-signing-runtime.js';
import {
  publishNotificationDeliveryStart,
  readNotificationDeliveryStartInTransaction,
} from './delivery-start-atomic.js';
import {
  claimNotificationDeliveryDispatch,
  consumeNotificationDispatchCapability,
  readNotificationDeliveryDispatch,
} from './delivery-dispatch-state.js';
import { withNotificationDeliveryMaterialContext } from './delivery-material-context.js';
import { currentNotificationChannel } from './endpoint-admission.js';
import { deliverNotificationProvider, reconcileNotificationProvider } from './delivery-provider.js';
import {
  prepareNotificationOutcomeSigning,
  notificationOutcomeSigningSelector,
} from './delivery-outcome-state.js';
import { NotificationOutcomeSigningRecovery } from './delivery-outcome-runtime.js';
import {
  publishNotificationDeliveryOutcome,
  readNotificationDeliveryOutcomePublication,
} from './delivery-outcome-publication.js';

const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const signers = z.strictObject({ start: digest, outcome: digest });
const originalSchema = z
  .strictObject({
    source: notificationDeliverySourceSelector,
    start: notificationDeliverySigningSelector.optional(),
    outcome: notificationOutcomeSigningSelector.optional(),
  })
  .refine(
    (v) =>
      (!v.start || canonicalJson(v.source) === canonicalJson(v.start.source)) &&
      (!v.outcome ||
        (v.start &&
          canonicalJson(v.outcome.original) === canonicalJson(v.start) &&
          canonicalJson(v.outcome.worker) === canonicalJson(v.source.worker))),
  );
export type NotificationDeliveryOriginal = z.infer<typeof originalSchema>;
export interface NotificationDeliveryPeers {
  readonly delivery: TLSSocket;
  readonly recipient: TLSSocket;
}
export interface NotificationDeliveryRuntimeOptions {
  /** Borrowed actual owners; this adapter never creates a Pool or a listener. */
  readonly pool: Pool;
  readonly kernel: IdentityKernel;
  readonly vaultDirectory: string;
  readonly kmsTls: EvidenceKmsTlsMaterial;
  readonly signerTls: ConstructorParameters<typeof NotificationOutcomeSigningRecovery>[2];
  readonly signers: z.infer<typeof signers>;
  readonly credentialProvider: NotificationCredentialProvider;
}
export class NotificationDeliveryRuntimeError extends Error {
  constructor(
    readonly code: 'INPUT' | 'CLOSED' | 'BUSY' | 'UNKNOWN',
    readonly original?: NotificationDeliveryOriginal,
    options?: ErrorOptions,
  ) {
    super(`Notification delivery runtime ${code}`, options);
  }
}
/** Composition only, NOT the missing signed async/consumer admission. The root
 * must remain unwired until that admission exists. No polling, listener, queue,
 * invented qualification, observation injection or caller-ready callback. */
export class NotificationDeliveryRuntime {
  readonly packagingStatus = Object.freeze({
    state: 'UNWIRED' as const,
    missing: Object.freeze([
      'CURRENT_ASYNC_CONSUMER_ADMISSION',
      'CANONICAL_ROOT_INVOCATION',
    ] as const),
  });
  private readonly stop = new AbortController();
  private active: Promise<unknown> | undefined;
  private closing: Promise<void> | undefined;
  private readonly pool: Pool;
  private readonly kernel: IdentityKernel;
  private readonly credentialProvider: NotificationCredentialProvider;
  private readonly signerTls: NotificationDeliveryRuntimeOptions['signerTls'];
  private readonly kmsTls: EvidenceKmsTlsMaterial;
  private readonly signers: z.infer<typeof signers>;
  private readonly gate: NotificationPayloadReferenceGate;
  private readonly material: NotificationDeliveryMaterial;
  private readonly kms: EvidenceKmsRuntime;
  constructor(options: NotificationDeliveryRuntimeOptions) {
    if (
      !(options.pool instanceof Pool) ||
      !(options.kernel instanceof IdentityKernel) ||
      typeof options.credentialProvider?.withExactVersion !== 'function' ||
      typeof options.vaultDirectory !== 'string' ||
      !options.vaultDirectory.startsWith('/')
    )
      throw new NotificationDeliveryRuntimeError('INPUT');
    this.signers = signers.parse(immutableJsonCopy(options.signers));
    const material = [
      options.kmsTls.ca,
      options.kmsTls.certificate,
      options.kmsTls.privateKey,
      options.signerTls.trustCa,
      options.signerTls.certificate,
      options.signerTls.privateKey,
    ];
    if (
      !material.every((b) => Buffer.isBuffer(b) && b.length > 0 && b.length <= 65536) ||
      (options.signerTls.timeoutMs !== undefined &&
        (!Number.isInteger(options.signerTls.timeoutMs) ||
          options.signerTls.timeoutMs < 50 ||
          options.signerTls.timeoutMs > 10000))
    )
      throw new NotificationDeliveryRuntimeError('INPUT');
    this.pool = options.pool;
    this.kernel = options.kernel;
    this.credentialProvider = options.credentialProvider;
    this.kmsTls = {
      ca: Buffer.from(options.kmsTls.ca),
      certificate: Buffer.from(options.kmsTls.certificate),
      privateKey: Buffer.from(options.kmsTls.privateKey),
    };
    this.signerTls = {
      trustCa: Buffer.from(options.signerTls.trustCa),
      certificate: Buffer.from(options.signerTls.certificate),
      privateKey: Buffer.from(options.signerTls.privateKey),
      ...(options.signerTls.timeoutMs === undefined
        ? {}
        : { timeoutMs: options.signerTls.timeoutMs }),
    };
    this.gate = new NotificationPayloadReferenceGate(options.vaultDirectory);
    this.material = new NotificationDeliveryMaterial(
      this.pool,
      this.kernel,
      this.kmsTls,
      options.vaultDirectory,
    );
    this.kms = new EvidenceKmsRuntime(this.pool, this.kernel, this.kmsTls);
  }
  private current() {
    if (this.stop.signal.aborted) throw new NotificationDeliveryRuntimeError('CLOSED');
  }
  private invoke<T>(peers: NotificationDeliveryPeers, use: () => Promise<T>): Promise<T> {
    this.current();
    // Local invocation exclusion, not a qualified worker concurrency setting.
    if (this.active) throw new NotificationDeliveryRuntimeError('BUSY');
    if (
      !(peers?.delivery instanceof TLSSocket) ||
      !(peers?.recipient instanceof TLSSocket) ||
      [peers.delivery, peers.recipient].some((p) => p.destroyed || !p.authorized)
    )
      throw new NotificationDeliveryRuntimeError('INPUT');
    const pending = Promise.resolve().then(() => {
      this.current();
      return use();
    });
    this.active = pending;
    void pending.then(
      () => {
        if (this.active === pending) this.active = undefined;
      },
      () => {
        if (this.active === pending) this.active = undefined;
      },
    );
    return pending;
  }
  private transport() {
    return { ...this.signerTls, signal: this.stop.signal };
  }
  private async refresh(
    peers: NotificationDeliveryPeers,
    source: NotificationDeliveryOriginal['source'],
  ) {
    this.current();
    const selector = await withNotificationDeliveryRequest(
      this.pool,
      this.kernel,
      peers.delivery,
      source,
      async (_client, admission, published) => ({
        recipient: {
          participantId: source.worker.participantId,
          privacyDomainId: source.worker.privacyDomainId,
          producerTrustDigest: admission.installation.profile.producerTrustDigest,
          installationDigest: admission.installation.profile.kmsInstallationDigest,
        },
        attemptId: published.claims.keyPreparationId,
      }),
    );
    this.current();
    await this.kms.observeCurrentStatus(peers.recipient, selector, this.stop.signal);
    this.current();
  }
  /** Starts at most the first original attempt. A retained preparation returns
   * ORIGINAL immediately: re-entry never allocates a retry or dispatches it. */
  start(peers: NotificationDeliveryPeers, value: unknown) {
    const source = notificationDeliverySourceSelector.parse(immutableJsonCopy(value));
    return this.startOriginal(peers, source);
  }
  startLeased(peers: NotificationDeliveryPeers, leaseValue: unknown, value: unknown) {
    const lease = notificationWorkerLeaseSelector.parse(immutableJsonCopy(leaseValue));
    const source = notificationDeliverySourceSelector.parse(immutableJsonCopy(value));
    return this.startOriginal(peers, source, lease);
  }
  /** Retry is explicit and selects the signed original outcome, never an elapsed
   * timeout or a caller's assertion of no effect. */
  retryLeased(peers: NotificationDeliveryPeers, leaseValue: unknown, value: unknown) {
    const lease = notificationWorkerLeaseSelector.parse(immutableJsonCopy(leaseValue));
    const retry = notificationOutcomeSigningSelector.parse(immutableJsonCopy(value));
    if (
      retry.original.signerInstallationDigest !== this.signers.start ||
      retry.signerInstallationDigest !== this.signers.outcome
    )
      throw new NotificationDeliveryRuntimeError('INPUT');
    return this.startOriginal(peers, retry.original.source, lease, retry);
  }
  /** Explicit crash recovery of the same unhanded-off preparation. Ordinary
   * start() still returns ORIGINAL and lookup() never begins a new phase. */
  async resumePreEffectLeased(
    peers: NotificationDeliveryPeers,
    leaseValue: unknown,
    value: unknown,
  ) {
    this.current();
    const lease = notificationWorkerLeaseSelector.parse(immutableJsonCopy(leaseValue));
    const source = notificationDeliverySourceSelector.parse(immutableJsonCopy(value));
    const resume = await inspectNotificationPreEffectResume(
      this.pool,
      this.kernel,
      peers.delivery,
      source,
      lease,
    );
    this.current();
    return this.startOriginal(peers, source, lease, undefined, resume.operationId);
  }
  private startOriginal(
    peers: NotificationDeliveryPeers,
    source: NotificationDeliveryOriginal['source'],
    lease?: NotificationWorkerLeaseSelector,
    retry?: NotificationOutcomeSigningSelector,
    resumeOperationId?: string | null,
  ) {
    return this.invoke(peers, async () => {
      let original: NotificationDeliveryOriginal = retry
        ? { source, start: retry.original, outcome: retry }
        : { source };
      let mutation = false;
      try {
        const retained = await readNotificationDeliveryPreparation(
          this.pool,
          this.kernel,
          peers.delivery,
          source,
        );
        this.current();
        if (resumeOperationId && retained?.operationId !== resumeOperationId)
          throw new NotificationDeliveryRuntimeError('UNKNOWN', original);
        if (
          retained &&
          retained.operationId !== resumeOperationId &&
          (!retry || retained.operationId !== retry.original.operationId)
        )
          return {
            state: 'ORIGINAL' as const,
            // A mount's current signer selection is not proof of the original
            // signing installation. Return retained bytes without inventing it.
            original: { source: retained.source },
            preparation: retained,
          };
        const configuration = await withNotificationDeliveryConfiguration(
          this.pool,
          this.kernel,
          peers.delivery,
          source,
          async (_client, _admission, _source, configuration) => configuration,
        );
        this.current();
        if (configuration.configured_limit === 0)
          return { state: 'WAIT' as const, reason: 'ZERO_CAPACITY' as const, original };
        mutation = true;
        await (
          lease
            ? synchronizeNotificationDeliveryBudgetLeased.bind(undefined, lease)
            : synchronizeNotificationDeliveryBudget
        )(this.pool, this.kernel, peers.delivery, source);
        this.current();
        const retried =
          retry && lease
            ? await prepareNotificationRetryDeliveryLeased(
                lease,
                this.pool,
                this.kernel,
                peers.delivery,
                retry,
              )
            : undefined;
        if (retried?.state === 'ORIGINAL')
          return { state: 'ORIGINAL' as const, original, preparation: retried.preparation };
        const prepared =
          retried?.preparation ??
          (await (
            lease
              ? prepareNotificationDeliveryLeased.bind(undefined, lease)
              : prepareNotificationDelivery
          )(this.pool, this.kernel, peers.delivery, source));
        if (
          retry &&
          (prepared.operationId === retry.original.operationId ||
            prepared.before.attemptCount !== retained?.attempt.attemptNumber)
        )
          return { state: 'ORIGINAL' as const, original, preparation: prepared };
        const selector = {
          source: prepared.source,
          operationId: prepared.operationId,
          signerInstallationDigest: this.signers.start,
        };
        original = { source: prepared.source, start: selector };
        await this.refresh(peers, source);
        await (
          lease
            ? prepareNotificationDeliverySigningLeased.bind(undefined, lease)
            : prepareNotificationDeliverySigning
        )(this.pool, this.kernel, peers.delivery, this.gate, selector);
        this.current();
        const signing = new NotificationDeliverySigningRuntime(
          this.pool,
          this.kernel,
          this.gate,
          this.transport(),
        );
        const signed = await (lease
          ? signing.dispatchOnceLeased(peers.delivery, selector, lease)
          : signing.dispatchOnce(peers.delivery, selector));
        this.current();
        if (signed.state !== 'OBSERVED' || signed.record.observation?.outcome !== 'SIGNED')
          throw new NotificationDeliveryRuntimeError('UNKNOWN', original);
        await this.refresh(peers, source);
        const started = await (
          lease
            ? publishNotificationDeliveryStartLeased.bind(undefined, lease)
            : publishNotificationDeliveryStart
        )(this.pool, this.kernel, peers.delivery, this.gate, selector);
        await this.refresh(peers, source);
        const claim = await (
          lease
            ? claimNotificationDeliveryDispatchLeased.bind(undefined, lease)
            : claimNotificationDeliveryDispatch
        )(this.pool, this.kernel, peers.delivery, this.gate, selector);
        this.current();
        if (claim.state === 'WAIT')
          return { state: 'WAIT' as const, reason: claim.reason, original };
        if (claim.state === 'LOOKUP') return { state: 'ORIGINAL' as const, original };
        let observation: Awaited<ReturnType<typeof deliverNotificationProvider>> | undefined;
        await (
          lease
            ? withNotificationDeliveryMaterialContextLeased.bind(undefined, lease)
            : withNotificationDeliveryMaterialContext
        )(this.pool, this.kernel, peers.delivery, this.gate, selector, async (context) => {
          // Only the actual live callback consumes the once-only durable claim.
          const claimed = consumeNotificationDispatchCapability(claim.capability, selector);
          if (canonicalJson(claimed.original) !== canonicalJson(started))
            throw new NotificationDeliveryRuntimeError('UNKNOWN', original);
          this.current();
          const channel = await currentNotificationChannel(
            context.client,
            source.worker,
            started.attempt.credentialRef,
          );
          await this.material.consume(
            context,
            peers.recipient,
            lease
              ? notificationWorkerLeaseSignal(
                  context.leaseWindow ??
                    (() => {
                      throw new NotificationDeliveryRuntimeError('UNKNOWN', original);
                    })(),
                  this.stop.signal,
                )
              : this.stop.signal,
            async (plaintext, window) => {
              this.current();
              await withNotificationSecretRecipient(
                this.pool,
                this.kernel,
                peers.recipient,
                this.recipient(channel.credential),
                this.credentialProvider,
                async (lease) => {
                  this.current();
                  observation = await deliverNotificationProvider(
                    {
                      original: started,
                      current: channel.channel,
                      credential: channel.credential,
                      lease,
                      window,
                    },
                    plaintext,
                  );
                },
              );
            },
          );
        });
        this.current();
        if (!observation) throw new NotificationDeliveryRuntimeError('UNKNOWN', original);
        const outcome = await (
          lease
            ? prepareNotificationOutcomeSigningLeased.bind(undefined, lease)
            : prepareNotificationOutcomeSigning
        )(this.pool, this.kernel, peers.delivery, {
          original: selector,
          worker: source.worker,
          signerInstallationDigest: this.signers.outcome,
          expectedRevision: String(BigInt(started.receipt.deliveryRevision) + 1n),
          observation,
        });
        original = { source: prepared.source, start: selector, outcome: outcome.selector };
        this.current();
        const recovery = new NotificationOutcomeSigningRecovery(
          this.pool,
          this.kernel,
          this.transport(),
        );
        const result = await (lease
          ? recovery.dispatchOnceLeased(peers.delivery, outcome.selector, lease)
          : recovery.dispatchOnce(peers.delivery, outcome.selector));
        this.current();
        if (result.state !== 'OBSERVED' || result.record.observation?.outcome !== 'SIGNED')
          throw new NotificationDeliveryRuntimeError('UNKNOWN', original);
        const publication = await (
          lease
            ? publishNotificationDeliveryOutcomeLeased.bind(undefined, lease)
            : publishNotificationDeliveryOutcome
        )(this.pool, this.kernel, peers.delivery, outcome.selector);
        this.current();
        return { state: 'PUBLISHED' as const, original, publication };
      } catch (cause) {
        if (mutation) throw new NotificationDeliveryRuntimeError('UNKNOWN', original, { cause });
        throw cause;
      }
    });
  }
  private recipient(c: Awaited<ReturnType<typeof currentNotificationChannel>>['credential']) {
    const { participantId, privacyDomainId, credentialRef, reference, version, epoch } = c;
    return { participantId, privacyDomainId, credentialRef, reference, version, epoch };
  }
  /** Original lookup only. No prepare, claim, publish, unwrap or perform path.
   * A result/absence does not authorize resubmission or renew the original. */
  lookup(peers: NotificationDeliveryPeers, value: unknown) {
    const q = originalSchema.parse(immutableJsonCopy(value));
    if (
      (q.start && q.start.signerInstallationDigest !== this.signers.start) ||
      (q.outcome && q.outcome.signerInstallationDigest !== this.signers.outcome)
    )
      throw new NotificationDeliveryRuntimeError('INPUT');
    return this.invoke(peers, async () => {
      try {
        const preparation = await readNotificationDeliveryPreparation(
          this.pool,
          this.kernel,
          peers.delivery,
          q.source,
        );
        this.current();
        if (!q.start) return { state: 'ORIGINAL' as const, original: q, preparation };
        if (q.outcome) {
          const publication = await readNotificationDeliveryOutcomePublication(
            this.pool,
            this.kernel,
            peers.delivery,
            q.outcome,
          );
          this.current();
          if (publication) return { state: 'PUBLISHED' as const, original: q, publication };
          const signing = await new NotificationOutcomeSigningRecovery(
            this.pool,
            this.kernel,
            this.transport(),
          ).reconcile(peers.delivery, q.outcome);
          this.current();
          return { state: 'ORIGINAL' as const, original: q, signing };
        }
        const signing = await new NotificationDeliverySigningRuntime(
          this.pool,
          this.kernel,
          this.gate,
          this.transport(),
        ).reconcile(peers.delivery, q.start);
        this.current();
        if (signing.state !== 'OBSERVED')
          return { state: 'ORIGINAL' as const, original: q, signing };
        const start = await withNotificationSigningHistory(
          this.pool,
          this.kernel,
          peers.delivery,
          q.start,
          (client, selector) => readNotificationDeliveryStartInTransaction(client, selector),
        );
        this.current();
        if (!start) return { state: 'ORIGINAL' as const, original: q, signing };
        const dispatch = await readNotificationDeliveryDispatch(
          this.pool,
          this.kernel,
          peers.delivery,
          q.start,
        );
        this.current();
        if (dispatch.claim.state !== 'CLAIMED')
          return { state: 'ORIGINAL' as const, original: q, dispatch };
        const gateway = await withNotificationDeliveryRequest(
          this.pool,
          this.kernel,
          peers.delivery,
          q.source,
          async (client) => {
            const channel = await currentNotificationChannel(
              client,
              q.source.worker,
              dispatch.original.attempt.credentialRef,
            );
            return withNotificationSecretRecipient(
              this.pool,
              this.kernel,
              peers.recipient,
              this.recipient(channel.credential),
              this.credentialProvider,
              async (lease) => {
                this.current();
                return reconcileNotificationProvider({
                  original: dispatch.original,
                  current: channel.channel,
                  credential: channel.credential,
                  lease,
                  window: {
                    signal: this.stop.signal,
                    timeoutMs: channel.channel.transport.requestTimeoutMs,
                  },
                });
              },
            );
          },
        );
        this.current();
        return { state: 'ORIGINAL' as const, original: q, dispatch, gateway };
      } catch (cause) {
        throw new NotificationDeliveryRuntimeError('UNKNOWN', q, { cause });
      }
    });
  }
  /** New mutation of an observed original remains separately lease admitted.
   * lookup() itself stays read/reconcile-only. No recovered path invokes a
   * gateway deliver or re-signs an unknown signer request. */
  async recoverLeased(peers: NotificationDeliveryPeers, leaseValue: unknown, value: unknown) {
    const lease = notificationWorkerLeaseSelector.parse(immutableJsonCopy(leaseValue));
    const q = originalSchema.parse(immutableJsonCopy(value));
    const found = await this.lookup(peers, q);
    if (found.state === 'PUBLISHED') return found;
    return this.invoke(peers, async () => {
      let original = q;
      try {
        if (
          q.outcome &&
          'signing' in found &&
          found.signing?.state === 'OBSERVED' &&
          found.signing.record.observation?.outcome === 'SIGNED'
        ) {
          const publication = await publishNotificationDeliveryOutcomeLeased(
            lease,
            this.pool,
            this.kernel,
            peers.delivery,
            q.outcome,
          );
          return { state: 'PUBLISHED' as const, original, publication };
        }
        if (q.start && 'gateway' in found && found.gateway) {
          const outcome = await prepareNotificationOutcomeSigningLeased(
            lease,
            this.pool,
            this.kernel,
            peers.delivery,
            {
              original: q.start,
              worker: q.source.worker,
              signerInstallationDigest: this.signers.outcome,
              expectedRevision: String(
                BigInt(found.dispatch.original.receipt.deliveryRevision) + 1n,
              ),
              observation: found.gateway,
            },
          );
          original = { ...q, outcome: outcome.selector };
          const signer = new NotificationOutcomeSigningRecovery(
            this.pool,
            this.kernel,
            this.transport(),
          );
          const signed = await signer.dispatchOnceLeased(peers.delivery, outcome.selector, lease);
          if (signed.state !== 'OBSERVED' || signed.record.observation?.outcome !== 'SIGNED')
            throw new NotificationDeliveryRuntimeError('UNKNOWN', original);
          const publication = await publishNotificationDeliveryOutcomeLeased(
            lease,
            this.pool,
            this.kernel,
            peers.delivery,
            outcome.selector,
          );
          return { state: 'PUBLISHED' as const, original, publication };
        }
        return found;
      } catch (cause) {
        throw new NotificationDeliveryRuntimeError('UNKNOWN', original, { cause });
      }
    });
  }
  /** Stop is immediate, drain is awaited. Borrowed peers/Pool/Identity are never
   * destroyed here. A stopped callback cannot advance another phase. */
  close(): Promise<void> {
    if (this.closing) return this.closing;
    this.stop.abort();
    const active = this.active;
    this.closing = (async () => {
      try {
        await active;
      } finally {
        for (const bytes of [
          this.signerTls.trustCa,
          this.signerTls.certificate,
          this.signerTls.privateKey,
          this.kmsTls.ca,
          this.kmsTls.certificate,
          this.kmsTls.privateKey,
        ])
          bytes.fill(0);
      }
    })();
    return this.closing;
  }
}
