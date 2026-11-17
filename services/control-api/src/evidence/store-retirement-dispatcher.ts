import { execFile } from 'node:child_process';
import { sign, type KeyObject } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';
import { PostgresStoreRetirementWorkerStore } from './store-retirement-worker-store.js';
import {
  parseRetirementWire,
  retirementCancellationClaims,
  retirementHost,
  retirementPurposes,
  retirementWireBytes,
  retirementWireDigest,
  type StoreRetirementAttempt,
  type StoreRetirementHost,
} from './store-retirement-wire.js';

const targetResponse = z.strictObject({
  identity: z.enum(['OPENPC-FACT-RETIREMENT-TARGET-1', 'OPENPC-CANDIDATE-RETIREMENT-TARGET-1']),
  hostDigest: z.string().regex(/^[0-9a-f]{64}$/u),
  result: z.discriminatedUnion('state', [
    z.strictObject({ state: z.literal('UNKNOWN') }),
    z.strictObject({
      state: z.literal('TERMINAL'),
      signedWireHex: z
        .string()
        .min(2)
        .max(2097152)
        .regex(/^(?:[0-9a-f]{2})+$/u),
    }),
  ]),
});

export function parseStoreRetirementTarget(
  bytes: Buffer,
  host: StoreRetirementHost,
  readOnly: boolean,
) {
  const response = targetResponse.parse(parseRetirementWire(bytes));
  if (
    response.identity !==
      (host.store === 'openpc_facts'
        ? 'OPENPC-FACT-RETIREMENT-TARGET-1'
        : 'OPENPC-CANDIDATE-RETIREMENT-TARGET-1') ||
    response.hostDigest !== retirementWireDigest(retirementHost.parse(host)) ||
    (!readOnly && response.result.state === 'UNKNOWN')
  )
    throw new Error('Retirement target binding unavailable');
  return response.result.state === 'UNKNOWN'
    ? undefined
    : Buffer.from(response.result.signedWireHex, 'hex');
}

/** Fact-specific compatibility entrypoint rejects a candidate target. */
export function parseFactRetirementTarget(
  bytes: Buffer,
  host: StoreRetirementHost,
  readOnly: boolean,
) {
  if (host.store !== 'openpc_facts') throw new Error('Fact retirement target binding unavailable');
  return parseStoreRetirementTarget(bytes, host, readOnly);
}

/** Host-installed worker only. Public HTTP inputs cannot choose the executable,
 * connection, signing key or target trust. Target signatures are verified by
 * the durable worker store before any terminal state becomes visible. */
export class StoreRetirementDispatcher {
  private readonly host: StoreRetirementHost;
  constructor(
    private readonly store: PostgresStoreRetirementWorkerStore,
    host: StoreRetirementHost,
    private readonly controlKey: KeyObject,
    private readonly targetConfigurationFile: string,
  ) {
    this.host = retirementHost.parse(structuredClone(host));
    if (
      !targetConfigurationFile.startsWith('/') ||
      controlKey.type !== 'private' ||
      controlKey.asymmetricKeyType !== 'ec' ||
      controlKey.asymmetricKeyDetails?.namedCurve !== 'prime256v1'
    )
      throw new Error('Invalid installed retirement dispatcher');
  }
  private signed(purpose: 'request' | 'cancel', claims: Parameters<typeof retirementWireBytes>[0]) {
    const claims_digest = retirementWireDigest(claims);
    return retirementWireBytes({
      purpose: retirementPurposes[purpose],
      claims,
      claims_digest,
      signature_p1363_hex: sign(
        'sha256',
        retirementWireBytes([retirementPurposes[purpose], claims_digest]),
        { key: this.controlKey, dsaEncoding: 'ieee-p1363' },
      ).toString('hex'),
    });
  }
  private async target(
    attempt: StoreRetirementAttempt,
    wire?: Buffer,
    purpose?: 'REQUEST' | 'CANCEL',
  ) {
    const input = wire
      ? retirementWireBytes({
          mode: purpose === 'REQUEST' ? 'EXECUTE' : 'CANCEL',
          signed_wire_hex: wire.toString('hex'),
        })
      : retirementWireBytes({ mode: 'READBACK', attempt });
    const fact = this.host.store === 'openpc_facts';
    const executable = fact
      ? (process.env.OPENPC_FACT_RETIREMENT_OWNER_BIN ??
        fileURLToPath(new URL('../../../../target/debug/fact_retirement_owner', import.meta.url)))
      : (process.env.OPENPC_CANDIDATE_RETIREMENT_OWNER_BIN ??
        fileURLToPath(
          new URL('../../../../target/debug/candidate_retirement_owner', import.meta.url),
        ));
    const response = await new Promise<Buffer>((resolve, reject) => {
      const child = execFile(
        executable,
        [],
        {
          env: {
            ...process.env,
            [fact
              ? 'OPENPC_RETIREMENT_FACT_CONFIGURATION_FILE'
              : 'OPENPC_RETIREMENT_CANDIDATE_CONFIGURATION_FILE']: this.targetConfigurationFile,
          },
          timeout: 20000,
          maxBuffer: 2098176,
          encoding: 'buffer',
        },
        (error, stdout) => {
          if (error) reject(new Error('Retirement target unavailable; reconcile original attempt'));
          else resolve(stdout);
        },
      );
      child.stdin?.on('error', () => reject(new Error('Retirement target input unavailable')));
      if (!child.stdin) reject(new Error('Retirement target input unavailable'));
      else child.stdin.end(input);
    });
    return parseStoreRetirementTarget(response, this.host, wire === undefined);
  }
  async runAttempt(attemptId: string) {
    const existing = await this.store.readOutcome(attemptId);
    if (existing.state !== 'UNKNOWN') return existing;
    const attempt = await this.store.readAttempt(attemptId);
    const target = await this.target(attempt);
    if (target) return this.store.recordOutcome(attemptId, target);
    const cancellation = await this.store.readCancellation(attemptId);
    let delivery;
    if (cancellation || (await this.store.needsCancellation(attemptId))) {
      const committed = cancellation ?? (await this.store.commitCancellation(attemptId));
      const now = BigInt(Date.now());
      const claims = retirementCancellationClaims(
        {
          version: 1n,
          host: this.host,
          attempt,
          cancellation_id: committed.cancellationId,
          lifecycle_revision: BigInt(committed.lifecycleRevision),
          committed_cancellation_digest: committed.committedDigest,
          issued_at_ms: now,
          expires_at_ms: now + 60000n,
        },
        this.host,
        now,
      );
      delivery = await this.store.recordDelivery(
        attemptId,
        'CANCEL',
        this.signed('cancel', claims),
      );
    } else {
      const claims = await this.store.prepareRequest(attemptId);
      delivery = await this.store.recordDelivery(
        attemptId,
        'REQUEST',
        this.signed('request', claims),
      );
    }
    const outcome = await this.store.dispatchDelivery(
      attemptId,
      delivery.deliveryId,
      (wire, purpose) => this.target(attempt, wire, purpose),
    );
    if (!outcome) throw new Error('Retirement target returned no terminal result');
    return this.store.recordOutcome(attemptId, outcome);
  }
}
