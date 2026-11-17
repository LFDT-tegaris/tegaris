import { createHash, createHmac, createPublicKey, randomBytes, type KeyObject } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import { z } from 'zod';
import { uuidv7 } from '../configuration/governed-mutation-http.js';
import {
  parseRetirementWire,
  retirementAttempt,
  retirementAttemptDigest,
  retirementHost,
  retirementRequestClaims,
  retirementWireBytes,
  verifyRetirementCancellation,
  verifyRetirementOutcome,
  verifyRetirementRequest,
  type StoreRetirementAttempt,
  type StoreRetirementHost,
} from './store-retirement-wire.js';

const digest = (bytes: Buffer) => createHash('sha256').update(bytes).digest();
const uuidBytes = (value: string) =>
  Buffer.from(z.uuidv7().parse(value).replaceAll('-', ''), 'hex');
const action = 'ACT-EVIDENCE_DELETIONS_RECONCILE_STORE_BATCH-V1';
const originalRow = z.strictObject({
  attemptWire: z.instanceof(Buffer),
  attemptDigest: z.string().regex(/^[0-9a-f]{64}$/u),
  hostWire: z.instanceof(Buffer),
  controlSpki: z.instanceof(Buffer),
  targetSpki: z.instanceof(Buffer),
});

/** An uncertain database COMMIT must be reconciled by primary readback, never by
 * repeating a physical request or treating a missing target row as no effect. */
export class StoreRetirementCommitUnknown extends Error {
  constructor(readonly recordId: string) {
    super('Store retirement commit requires reconciliation');
  }
}
export type StoreRetirementReadback =
  | { state: 'UNKNOWN' }
  | { state: 'APPLIED' | 'REJECTED_NO_EFFECT' | 'CANCELLED_NO_EFFECT'; signedWire: Buffer };

/** Durable Control worker boundary. The installed process owns the verifier
 * secret. This owner never signs a request, grants admission or performs target
 * I/O; it verifies host-pinned signed bytes and commits them before dispatch.
 * Historical delivery readback is not a dispatch grant: the native dispatcher
 * must still fence current authority/lifecycle and reconcile cancellation. */
export class PostgresStoreRetirementWorkerStore {
  private readonly host: StoreRetirementHost;
  private readonly hostDigest: string;
  private readonly secret: Buffer;
  private closed = false;
  constructor(
    private readonly pool: Pool,
    host: StoreRetirementHost,
    verifierSecret: Buffer,
  ) {
    this.host = retirementHost.parse(structuredClone(host));
    uuidBytes(this.host.scope.participant_id);
    uuidBytes(this.host.scope.privacy_domain_id);
    this.hostDigest = digest(retirementWireBytes(this.host)).toString('hex');
    if (verifierSecret.length !== 32) throw new Error('Invalid retirement verifier key');
    this.secret = Buffer.from(verifierSecret);
  }
  close() {
    this.closed = true;
    this.secret.fill(0);
  }
  private async begin(client: PoolClient) {
    if (this.closed) throw new Error('Retirement worker closed');
    await client.query('begin');
    await client.query('set local synchronous_commit=on');
    await client.query('set local row_security=on');
    await client.query("set local statement_timeout='10s'");
    await client.query("set local idle_in_transaction_session_timeout='10s'");
    await client.query("select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)", [
      this.host.scope.participant_id,
      this.host.scope.privacy_domain_id,
      uuidv7(),
      action,
    ]);
  }
  private async transaction<T>(
    recordId: string | undefined,
    work: (client: PoolClient) => Promise<T>,
  ): Promise<T> {
    const client = await this.pool.connect();
    let committing = false;
    try {
      await this.begin(client);
      const result = await work(client);
      committing = true;
      await client.query('commit');
      return result;
    } catch (error) {
      try {
        await client.query('rollback');
      } catch {
        /* Preserve the original uncertain result. */
      }
      if (committing && recordId) throw new StoreRetirementCommitUnknown(recordId);
      throw error;
    } finally {
      client.release();
    }
  }
  private scope(attemptId: string) {
    z.uuidv7().parse(attemptId);
    return [this.host.scope.participant_id, this.host.scope.privacy_domain_id, attemptId];
  }
  private async original(client: PoolClient, attemptId: string) {
    const result = await client.query(
      `select a.attempt_wire as "attemptWire",a.attempt_digest as "attemptDigest",
      h.host_wire as "hostWire",h.control_spki as "controlSpki",h.target_spki as "targetSpki"
      from control.store_retirement_admission a join control.store_retirement_host h using(participant_id,privacy_domain_id,host_digest)
      where a.participant_id=$1 and a.privacy_domain_id=$2 and a.attempt_id=$3 and a.host_digest=$4
       and a.xmin<>pg_current_xact_id()::xid`,
      [...this.scope(attemptId), this.hostDigest],
    );
    if (result.rowCount !== 1) throw new Error('Committed retirement admission unavailable');
    const row = originalRow.parse(result.rows[0]);
    const attempt = retirementAttempt.parse(parseRetirementWire(row.attemptWire));
    if (
      !retirementWireBytes(this.host).equals(row.hostWire) ||
      !retirementWireBytes(attempt).equals(row.attemptWire) ||
      retirementAttemptDigest(attempt) !== row.attemptDigest ||
      attempt.attempt_id !== attemptId ||
      attempt.scope.participant_id !== this.host.scope.participant_id ||
      attempt.scope.privacy_domain_id !== this.host.scope.privacy_domain_id ||
      attempt.store !== this.host.store
    )
      throw new Error('Retirement admission binding mismatch');
    const key = (bytes: Buffer): KeyObject =>
      createPublicKey({ key: bytes, type: 'spki', format: 'der' });
    return { attempt, controlKey: key(row.controlSpki), targetKey: key(row.targetSpki) };
  }
  private capability(
    domain: 'DELIVERY' | 'OUTCOME',
    attempt: StoreRetirementAttempt,
    wire: Buffer,
  ) {
    if (this.closed) throw new Error('Retirement worker closed');
    const nonce = randomBytes(32);
    const binding = digest(Buffer.concat([digest(retirementWireBytes(attempt)), digest(wire)]));
    const mac = createHmac('sha256', this.secret)
      .update(
        Buffer.concat([
          Buffer.from(`OPENPC_STORE_RETIREMENT_${domain}_COMMIT_V1`),
          uuidBytes(this.host.scope.participant_id),
          uuidBytes(this.host.scope.privacy_domain_id),
          Buffer.from(this.hostDigest, 'hex'),
          binding,
          nonce,
        ]),
      )
      .digest();
    return { nonce, mac };
  }
  /** Historical input for target readback, never permission to execute. */
  async readAttempt(attemptId: string) {
    return this.transaction(undefined, async (client) => {
      const original = await this.original(client, attemptId);
      await client.query('select openpc.lock_store_retirement_workload($1)', [this.hostDigest]);
      return original.attempt;
    });
  }
  private async lockDispatch(client: PoolClient, attemptId: string, purpose: 'REQUEST' | 'CANCEL') {
    if (purpose === 'REQUEST')
      await client.query('select openpc.lock_store_retirement_authority($1)', [attemptId]);
    else await client.query('select openpc.lock_store_retirement_workload($1)', [this.hostDigest]);
    await client.query(
      "select pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||$1::text,0))",
      [this.host.scope.participant_id],
    );
    if (purpose === 'REQUEST') {
      const result = await client.query(
        `select 1 from control.store_retirement_admission a
        where a.participant_id=$1 and a.privacy_domain_id=$2 and a.attempt_id=$3
         and openpc.store_retirement_source_binding(a.retention_policy_id,decode(a.source_binding->>'selectionWireHex','hex'),a.source_binding->'recordRefs')=a.source_binding
         and not exists(select 1 from control.store_retirement_cancellation c
          where c.participant_id=a.participant_id and c.privacy_domain_id=a.privacy_domain_id and c.attempt_id=a.attempt_id)
         and not exists(select 1 from control.store_retirement_outcome o
          where o.participant_id=a.participant_id and o.privacy_domain_id=a.privacy_domain_id and o.attempt_id=a.attempt_id)`,
        this.scope(attemptId),
      );
      if (result.rowCount !== 1) throw new Error('Retirement dispatch prerequisites changed');
    }
  }
  async prepareRequest(attemptId: string) {
    return this.transaction(undefined, async (client) => {
      const original = await this.original(client, attemptId);
      await this.lockDispatch(client, attemptId, 'REQUEST');
      const result = await client.query(
        `select a.dispatch_not_after_ms::text deadline,
         floor(extract(epoch from clock_timestamp())*1000)::text now,
         encode(r.receipt_digest,'hex') receipt,openpc.store_retirement_committed_digest(a) committed
        from control.store_retirement_admission a join control.audit_occurrence r
         on r.participant_id=a.participant_id and r.privacy_domain_id=a.privacy_domain_id and r.operation_id=a.operation_id
          and r.aggregate_type='store-retirement' and r.aggregate_id=a.attempt_id and r.profile_id='pc.control.store-retirement.admit'
        where a.participant_id=$1 and a.privacy_domain_id=$2 and a.attempt_id=$3`,
        this.scope(attemptId),
      );
      if (result.rowCount !== 1) throw new Error('Retirement receipt unavailable');
      const row = z
        .strictObject({
          deadline: z.string(),
          now: z.string(),
          receipt: z.string(),
          committed: z.string(),
        })
        .parse(result.rows[0]);
      const now = BigInt(row.now);
      return retirementRequestClaims(
        {
          version: 1n,
          host: this.host,
          attempt: original.attempt,
          admission_receipt_digest: row.receipt,
          committed_admission_digest: row.committed,
          issued_at_ms: now,
          expires_at_ms: BigInt(row.deadline),
        },
        this.host,
        now,
      );
    });
  }
  async needsCancellation(attemptId: string) {
    return this.transaction(undefined, async (client) => {
      await this.original(client, attemptId);
      await client.query('select openpc.lock_store_retirement_workload($1)', [this.hostDigest]);
      const result = await client.query(
        `select 1 from control.store_retirement_admission a where a.participant_id=$1 and a.privacy_domain_id=$2 and a.attempt_id=$3
         and (a.dispatch_not_after_ms<=floor(extract(epoch from clock_timestamp())*1000)
          or openpc.store_retirement_lifecycle_revision(a.participant_id,a.privacy_domain_id)<>a.lifecycle_revision
          or exists(select 1 from control.store_retirement_delivery d where d.participant_id=a.participant_id
           and d.privacy_domain_id=a.privacy_domain_id and d.attempt_id=a.attempt_id and d.purpose='REQUEST'))`,
        this.scope(attemptId),
      );
      return result.rowCount === 1;
    });
  }
  async pendingAttempts() {
    return this.transaction(undefined, async (client) => {
      await client.query('select openpc.lock_store_retirement_workload($1)', [this.hostDigest]);
      const result = await client.query(
        `select a.attempt_id::text from control.store_retirement_admission a
        where a.participant_id=$1 and a.privacy_domain_id=$2 and a.host_digest=$3
         and not exists(select 1 from control.store_retirement_outcome o where o.participant_id=a.participant_id
          and o.privacy_domain_id=a.privacy_domain_id and o.attempt_id=a.attempt_id)
        order by a.admitted_at,a.attempt_id limit 16`,
        [this.host.scope.participant_id, this.host.scope.privacy_domain_id, this.hostDigest],
      );
      return result.rows.map((row) => z.uuidv7().parse(row.attempt_id));
    });
  }
  /** The delivery is already committed. Keep the live human/workload and
   * lifecycle fences through the one bounded target call. A crash/lost response
   * is reconciled by target readback/cancellation, never a blind request retry. */
  async dispatchDelivery<T>(
    attemptId: string,
    deliveryId: string,
    send: (wire: Buffer, purpose: 'REQUEST' | 'CANCEL') => Promise<T>,
  ) {
    const delivery = await this.readDelivery(attemptId, deliveryId);
    if (!delivery) throw new Error('Committed retirement delivery unavailable');
    return this.transaction(undefined, async (client) => {
      const original = await this.original(client, attemptId);
      await this.lockDispatch(client, attemptId, delivery.purpose);
      const time = await client.query(
        'select floor(extract(epoch from clock_timestamp())*1000)::text now',
      );
      const now = BigInt(z.string().parse(time.rows[0]?.now));
      if (delivery.purpose === 'REQUEST')
        verifyRetirementRequest(delivery.signedWire, original.controlKey, this.host, now);
      else verifyRetirementCancellation(delivery.signedWire, original.controlKey, this.host, now);
      // The idle timeout must cover the configured native target's 20-second
      // process budget while the target serializes its own source/effect fence.
      await client.query("set local idle_in_transaction_session_timeout='25s'");
      return send(Buffer.from(delivery.signedWire), delivery.purpose);
    });
  }
  async readOutcome(attemptId: string): Promise<StoreRetirementReadback> {
    return this.transaction(undefined, async (client) => {
      const original = await this.original(client, attemptId);
      await client.query('select openpc.lock_store_retirement_workload($1)', [this.hostDigest]);
      const result = await client.query(
        `select signed_wire as wire from control.store_retirement_outcome
        where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3`,
        this.scope(attemptId),
      );
      if (result.rowCount === 0) return { state: 'UNKNOWN' };
      if (result.rowCount !== 1 || !Buffer.isBuffer(result.rows[0]?.wire))
        throw new Error('Invalid retirement outcome readback');
      const wire = result.rows[0].wire as Buffer;
      const claims = verifyRetirementOutcome(wire, original.targetKey, this.host, original.attempt);
      return { state: claims.outcome.effect.state, signedWire: Buffer.from(wire) };
    });
  }
  async recordOutcome(attemptId: string, signedWire: Buffer): Promise<StoreRetirementReadback> {
    const wire = Buffer.from(signedWire);
    await this.transaction(attemptId, async (client) => {
      const original = await this.original(client, attemptId);
      const claims = verifyRetirementOutcome(wire, original.targetKey, this.host, original.attempt);
      await client.query('select openpc.lock_store_retirement_workload($1)', [this.hostDigest]);
      await client.query(
        "select pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||$1::text,0))",
        [this.host.scope.participant_id],
      );
      const existing = await client.query(
        `select signed_wire from control.store_retirement_outcome
        where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3`,
        this.scope(attemptId),
      );
      if (existing.rowCount === 1) {
        if (!(existing.rows[0].signed_wire as Buffer).equals(wire))
          throw new Error('Original retirement outcome differs');
        return;
      }
      const proof = this.capability('OUTCOME', original.attempt, wire);
      await client.query(
        `insert into control.store_retirement_outcome(participant_id,privacy_domain_id,attempt_id,
       verification_nonce,verification_mac,state,signed_wire,wire_digest,completed_at_ms)
       values($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
        [
          ...this.scope(attemptId),
          proof.nonce,
          proof.mac,
          claims.outcome.effect.state,
          wire,
          digest(wire).toString('hex'),
          claims.completed_at_ms.toString(),
        ],
      );
    });
    const readback = await this.readOutcome(attemptId);
    if (readback.state === 'UNKNOWN' || !readback.signedWire.equals(wire))
      throw new StoreRetirementCommitUnknown(attemptId);
    return readback;
  }
  async recordDelivery(attemptId: string, purpose: 'REQUEST' | 'CANCEL', signedWire: Buffer) {
    const wire = Buffer.from(signedWire),
      deliveryId = uuidv7();
    await this.transaction(deliveryId, async (client) => {
      const original = await this.original(client, attemptId),
        now = BigInt(Date.now());
      const claims =
        purpose === 'REQUEST'
          ? verifyRetirementRequest(wire, original.controlKey, this.host, now)
          : verifyRetirementCancellation(wire, original.controlKey, this.host, now);
      if (!retirementWireBytes(claims.attempt).equals(retirementWireBytes(original.attempt)))
        throw new Error('Retirement delivery changed its original attempt');
      const proof = this.capability('DELIVERY', original.attempt, wire);
      await client.query(
        `insert into control.store_retirement_delivery(participant_id,privacy_domain_id,attempt_id,
        delivery_id,verification_nonce,verification_mac,purpose,signed_wire,wire_digest,issued_at_ms,expires_at_ms)
        values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
        [
          ...this.scope(attemptId),
          deliveryId,
          proof.nonce,
          proof.mac,
          purpose,
          wire,
          digest(wire).toString('hex'),
          claims.issued_at_ms.toString(),
          claims.expires_at_ms.toString(),
        ],
      );
    });
    const stored = await this.readDelivery(attemptId, deliveryId);
    if (!stored || !stored.signedWire.equals(wire))
      throw new StoreRetirementCommitUnknown(deliveryId);
    return stored;
  }
  async readDelivery(attemptId: string, deliveryId: string) {
    z.uuidv7().parse(deliveryId);
    return this.transaction(undefined, async (client) => {
      await this.original(client, attemptId);
      await client.query('select openpc.lock_store_retirement_workload($1)', [this.hostDigest]);
      const result = await client.query(
        `select signed_wire,purpose,expires_at_ms::text from control.store_retirement_delivery
        where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3 and delivery_id=$4`,
        [...this.scope(attemptId), deliveryId],
      );
      if (result.rowCount === 0) return undefined;
      const row = z
        .strictObject({
          signed_wire: z.instanceof(Buffer),
          purpose: z.enum(['REQUEST', 'CANCEL']),
          expires_at_ms: z.string().regex(/^[1-9][0-9]*$/u),
        })
        .parse(result.rows[0]);
      return {
        deliveryId,
        purpose: row.purpose,
        signedWire: Buffer.from(row.signed_wire),
        expiresAtMs: BigInt(row.expires_at_ms),
      };
    });
  }
  async commitCancellation(attemptId: string) {
    const cancellationId = uuidv7();
    await this.transaction(cancellationId, async (client) => {
      await this.original(client, attemptId);
      await client.query('select openpc.lock_store_retirement_workload($1)', [this.hostDigest]);
      await client.query(
        "select pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||$1::text,0))",
        [this.host.scope.participant_id],
      );
      const existing = await client.query(
        `select 1 from control.store_retirement_cancellation where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3`,
        this.scope(attemptId),
      );
      if (existing.rowCount === 1) return;
      await client.query(
        `insert into control.store_retirement_cancellation(participant_id,privacy_domain_id,attempt_id,cancellation_id,lifecycle_revision,cause,committed_digest)
       select participant_id,privacy_domain_id,attempt_id,$4,lifecycle_revision,
        case when openpc.store_retirement_lifecycle_revision(participant_id,privacy_domain_id)<>lifecycle_revision then
          jsonb_build_object('reason','LIFECYCLE_CHANGED','revision',openpc.store_retirement_lifecycle_revision(participant_id,privacy_domain_id)::text)
        when dispatch_not_after_ms<=floor(extract(epoch from clock_timestamp())*1000) then
          jsonb_build_object('reason','AUTHORITY_EXPIRED','dispatchNotAfterMs',dispatch_not_after_ms::text)
        else jsonb_build_object('reason','RECONCILE_UNKNOWN') end,repeat('0',64)
       from control.store_retirement_admission where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3`,
        [...this.scope(attemptId), cancellationId],
      );
    });
    const result = await this.readCancellation(attemptId);
    if (!result) throw new StoreRetirementCommitUnknown(cancellationId);
    return result;
  }
  async readCancellation(attemptId: string) {
    return this.transaction(undefined, async (client) => {
      await this.original(client, attemptId);
      await client.query('select openpc.lock_store_retirement_workload($1)', [this.hostDigest]);
      const result = await client.query(
        `select cancellation_id::text as "cancellationId",lifecycle_revision::text as "lifecycleRevision",committed_digest as "committedDigest"
        from control.store_retirement_cancellation where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3`,
        this.scope(attemptId),
      );
      if (result.rowCount === 0) return undefined;
      return z
        .strictObject({
          cancellationId: z.uuidv7(),
          lifecycleRevision: z.string().regex(/^[1-9][0-9]*$/u),
          committedDigest: z.string().regex(/^[0-9a-f]{64}$/u),
        })
        .parse(result.rows[0]);
    });
  }
}
