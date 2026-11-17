import { randomBytes } from 'node:crypto';
import { isAsyncFunction } from 'node:util/types';
import { localOperationId } from '../../../identity-service/src/domain/local-operation-id.js';
import type { Pool, PoolClient } from 'pg';
import type { TLSSocket } from 'node:tls';
import type { IdentityKernel } from '../../../identity-service/src/domain/identity-kernel.js';
import {
  assertEvidenceKeyAdmission,
  withEvidenceKeyRecipient,
} from '../../../identity-service/src/domain/evidence-key-recipient.js';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import {
  EvidenceKmsError,
  assertEvidenceKmsTransition,
  evidenceKmsAttemptSelector,
  evidenceKmsPrepareInput,
  evidenceKmsUnwrapInput,
  parseEvidenceKms,
  rejectEvidenceKms,
  verifyEvidenceKmsResponse,
  evidenceKmsReceiptBytes,
  type EvidenceKmsExpectedResponse,
  type EvidenceKmsAttemptSelector,
  type EvidenceKmsAttemptState,
  type EvidenceKmsPrepareInput,
} from './kms-contracts.js';
import { evidenceKmsAbsentDigest } from '../../../../packages/security-kernel/src/evidence-kms/codec.js';
import {
  inspectNotificationPayload,
  notificationPayloadBinding,
} from './notification-payload-crypto.js';

/** Ciphertext only, bound from the committed attempt and the local crypto result.
 * The existing ciphertext owner writes and rereads these exact bytes. Its SQL
 * writes may join this transaction; immutable file writes survive rollback and
 * must be reconciled through original readback, never deleted or resealed. */
export interface EvidenceKmsCiphertext {
  readonly participantId: string;
  readonly privacyDomainId: string;
  readonly payloadObjectId: string;
  readonly objectVersion: '1';
  readonly attemptId: string;
  readonly exchangeId: string;
  readonly originalRequestDigest: string;
  readonly objectIntentDigest: string;
  readonly keyId: string;
  readonly encryptedObjectDigest: string;
  readonly bytes: Buffer;
}
export type EvidenceKmsCiphertextPersistence = (
  client: PoolClient,
  ciphertext: EvidenceKmsCiphertext,
) => Promise<Buffer>;

/** No key material reaches this continuation. Exact readback bytes, rather than
 * a caller success flag, are required from the existing durable payload owner.
 * This does not make a cross-store commit atomic. */
export async function persistEvidenceKmsCiphertext(
  client: PoolClient,
  original: EvidenceKmsAttempt,
  selector: EvidenceKmsAttemptSelector,
  exchangeId: string,
  keyId: string,
  result: unknown,
  persist: EvidenceKmsCiphertextPersistence,
): Promise<void> {
  try {
    const prepared = inspectEvidenceKmsPrepareRequest(original.requestBytes);
    assertEvidenceKmsOriginal(original, selector);
    const property =
      result && typeof result === 'object'
        ? Object.getOwnPropertyDescriptor(result, 'bytes')
        : undefined;
    if (
      !property ||
      !('value' in property) ||
      !Buffer.isBuffer(property.value) ||
      property.value.length === 0 ||
      property.value.length > 131072
    )
      rejectEvidenceKms('INTEGRITY');
    const bytes = Buffer.from(property.value);
    const inspected = inspectNotificationPayload(bytes);
    const binding = { ...prepared.objectIntent, keyId };
    if (canonicalJson(inspected.header.binding) !== canonicalJson(binding))
      rejectEvidenceKms('INTEGRITY');
    const resultFields = [
      'binding',
      'bytes',
      'encryptionProfileDigest',
      'encryptionContextDigest',
      'encryptedObjectDigest',
    ];
    const assertResult = () => {
      if (
        !result ||
        typeof result !== 'object' ||
        Object.getPrototypeOf(result) !== Object.prototype ||
        Reflect.ownKeys(result).length !== resultFields.length
      )
        rejectEvidenceKms('INTEGRITY');
      const fields = Object.fromEntries(
        resultFields.map((name) => {
          const field = Object.getOwnPropertyDescriptor(result, name);
          if (!field || !('value' in field) || !field.enumerable) rejectEvidenceKms('INTEGRITY');
          return [name, field.value];
        }),
      );
      if (
        !Buffer.isBuffer(fields.bytes) ||
        !fields.bytes.equals(bytes) ||
        canonicalJson(parseEvidenceKms(notificationPayloadBinding, fields.binding)) !==
          canonicalJson(binding) ||
        fields.encryptionProfileDigest !== inspected.header.encryptionProfileDigest ||
        fields.encryptionContextDigest !== inspected.encryptionContextDigest ||
        fields.encryptedObjectDigest !== inspected.encryptedObjectDigest
      )
        rejectEvidenceKms('INTEGRITY');
    };
    assertResult();
    const ciphertext = Object.freeze({
      participantId: selector.recipient.participantId,
      privacyDomainId: selector.recipient.privacyDomainId,
      payloadObjectId: prepared.objectIntent.payloadObjectId,
      objectVersion: prepared.objectIntent.objectVersion,
      attemptId: original.attemptId,
      exchangeId,
      originalRequestDigest: original.requestDigest,
      objectIntentDigest: original.objectIntentDigest,
      keyId,
      encryptedObjectDigest: inspected.encryptedObjectDigest,
      bytes: Buffer.from(bytes),
    });
    const readback = await persist(client, ciphertext);
    assertResult();
    if (
      !Buffer.isBuffer(readback) ||
      !readback.equals(bytes) ||
      !ciphertext.bytes.equals(bytes) ||
      !property.value.equals(bytes)
    )
      rejectEvidenceKms('INTEGRITY');
  } catch (error) {
    if (error instanceof EvidenceKmsError) throw error;
    throw new EvidenceKmsError('UNKNOWN');
  }
}

/** Local crypto/persistence mechanics only, not admission. The actual state owner
 * supplies verified material under its Identity transaction. Exported for the
 * focused erasure/durability regression, using the real immutable file owner. */
export async function completeEvidenceKmsMaterial<T>(
  context: {
    client: PoolClient;
    original: EvidenceKmsAttempt;
    selector: EvidenceKmsAttemptSelector;
    exchangeId: string;
    keyId: string;
    material: Buffer;
    wire: Buffer;
    leaseUntilMs: number;
    receiptUntilMs: number;
  },
  use: (material: { keyId: string; bytes: Buffer; signal: AbortSignal }) => T,
  persist?: EvidenceKmsCiphertextPersistence,
): Promise<T> {
  const controller = new AbortController();
  try {
    let result: T;
    try {
      if (context.material.length !== 32 || isAsyncFunction(use)) rejectEvidenceKms('INVALID');
      if (Date.now() >= context.leaseUntilMs) rejectEvidenceKms('STALE');
      result = use({ keyId: context.keyId, bytes: context.material, signal: controller.signal });
    } finally {
      context.material.fill(0);
      context.wire.fill(0);
      controller.abort();
    }
    if (
      result !== null &&
      (typeof result === 'object' || typeof result === 'function') &&
      'then' in result
    ) {
      // A rejected accidental Promise must not become an unhandled rejection.
      void Promise.resolve(result).catch(() => undefined);
      rejectEvidenceKms('INVALID');
    }
    if (Date.now() >= context.leaseUntilMs) rejectEvidenceKms('STALE');
    if (persist) {
      await persistEvidenceKmsCiphertext(
        context.client,
        context.original,
        context.selector,
        context.exchangeId,
        context.keyId,
        result,
        persist,
      );
      if (Date.now() >= context.receiptUntilMs) rejectEvidenceKms('STALE');
    }
    return result;
  } catch (error) {
    if (error instanceof EvidenceKmsError) throw error;
    throw new EvidenceKmsError('UNKNOWN');
  }
}

export interface EvidenceKmsAttempt {
  readonly attemptId: string;
  readonly installationDigest: string;
  readonly objectIntentDigest: string;
  readonly authorityDigest: string;
  readonly requestBytes: Buffer;
  readonly requestDigest: string;
  readonly state: EvidenceKmsAttemptState;
  readonly resultReceiptBytes: Buffer | null;
}
interface AttemptRow {
  attempt_id: string;
  installation_digest: string;
  object_intent_digest: string;
  authority_digest: string;
  request_bytes: Buffer;
  request_digest: string;
  state: EvidenceKmsAttemptState;
  result_receipt_bytes: Buffer | null;
}

/** The registered profile's original canonical JSON request is committed once
 * with its unpredictable challenge; a retry cannot renew or re-encode it. */
export function inspectEvidenceKmsPrepareRequest(bytes: Buffer) {
  if (!Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.length > 32768)
    rejectEvidenceKms('INTEGRITY');
  try {
    const value: unknown = JSON.parse(bytes.toString('utf8'));
    if (!value || typeof value !== 'object' || Array.isArray(value)) rejectEvidenceKms('INTEGRITY');
    const { challenge, operation, ...input } = value as Record<string, unknown>;
    if (operation !== 'PREPARE') rejectEvidenceKms('INTEGRITY');
    if (typeof challenge !== 'string' || !/^[0-9a-f]{64}$/u.test(challenge))
      rejectEvidenceKms('INTEGRITY');
    const parsed = parseEvidenceKms(evidenceKmsPrepareInput, input);
    if (!Buffer.from(canonicalJson({ ...parsed, operation, challenge })).equals(bytes))
      rejectEvidenceKms('INTEGRITY');
    return { ...parsed, operation: 'PREPARE' as const, challenge };
  } catch {
    return rejectEvidenceKms('INTEGRITY');
  }
}

export function assertEvidenceKmsOriginal(
  attempt: EvidenceKmsAttempt,
  selector: EvidenceKmsAttemptSelector,
): void {
  const original = inspectEvidenceKmsPrepareRequest(attempt.requestBytes);
  if (
    attempt.attemptId !== selector.attemptId ||
    original.attemptId !== selector.attemptId ||
    attempt.installationDigest !== selector.recipient.installationDigest ||
    canonicalJson(original.recipient) !== canonicalJson(selector.recipient) ||
    attempt.requestDigest !== sha256(attempt.requestBytes) ||
    attempt.objectIntentDigest !== sha256(original.objectIntent)
  )
    rejectEvidenceKms('INTEGRITY');
}

function decode(row: AttemptRow): EvidenceKmsAttempt {
  return {
    attemptId: row.attempt_id,
    installationDigest: row.installation_digest,
    objectIntentDigest: row.object_intent_digest,
    authorityDigest: row.authority_digest,
    requestBytes: Buffer.from(row.request_bytes),
    requestDigest: row.request_digest,
    state: row.state,
    resultReceiptBytes: row.result_receipt_bytes && Buffer.from(row.result_receipt_bytes),
  };
}

/** Durable admission only. There is intentionally no injected provider, signer,
 * success callback or method accepting a self-asserted verified result. */
export class EvidenceKmsState {
  constructor(
    private readonly pool: Pool,
    private readonly kernel: IdentityKernel,
  ) {}

  private async select(client: PoolClient, selector: EvidenceKmsAttemptSelector) {
    const q = selector.recipient;
    const found = await client.query<AttemptRow>(
      `select attempt_id,installation_digest,object_intent_digest,
      authority_digest,request_bytes,request_digest,state,result_receipt_bytes
      from control.evidence_kms_attempt where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3 for update`,
      [q.participantId, q.privacyDomainId, selector.attemptId],
    );
    if (found.rowCount !== 1) rejectEvidenceKms('UNAVAILABLE');
    const attempt = decode(found.rows[0]!);
    assertEvidenceKmsOriginal(attempt, selector);
    return attempt;
  }

  async prepare(socket: TLSSocket, input: unknown): Promise<EvidenceKmsAttempt> {
    const parsed = parseEvidenceKms(evidenceKmsPrepareInput, input);
    const q = parsed.recipient,
      object = parsed.objectIntent;
    if (object.participantId !== q.participantId || object.privacyDomainId !== q.privacyDomainId)
      rejectEvidenceKms('SCOPE');
    return withEvidenceKeyRecipient(
      this.pool,
      this.kernel,
      socket,
      q,
      'ENCRYPT',
      async (client, admission) => {
        assertEvidenceKeyAdmission(admission, client, q);
        if (object.environmentId !== admission.installation.pins.environmentId)
          rejectEvidenceKms('SCOPE');
        await client.query(
          `select pg_advisory_xact_lock(hashtextextended('evidence-kms-object:'||$1::text||':'||$2::text||':'||$3::text,0))`,
          [q.participantId, q.privacyDomainId, object.payloadObjectId],
        );
        const prior = await client.query<{ attempt_id: string }>(
          `select attempt_id from control.evidence_kms_attempt
        where participant_id=$1 and privacy_domain_id=$2 and object_id=$3 and object_version=$4`,
          [q.participantId, q.privacyDomainId, object.payloadObjectId, object.objectVersion],
        );
        if (prior.rowCount) {
          if (prior.rowCount !== 1 || prior.rows[0]!.attempt_id !== parsed.attemptId)
            rejectEvidenceKms('CONFLICT');
          const result = await this.select(client, parsed);
          assertEvidenceKmsReplay(result, parsed);
          return result;
        }
        const request = {
          ...parsed,
          operation: 'PREPARE' as const,
          challenge: randomBytes(32).toString('hex'),
        };
        const bytes = Buffer.from(canonicalJson(request));
        await client.query(
          `insert into control.evidence_kms_attempt
        (participant_id,privacy_domain_id,attempt_id,installation_digest,object_id,object_version,object_intent_digest,
        authority_digest,request,request_bytes,request_digest) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
          [
            q.participantId,
            q.privacyDomainId,
            parsed.attemptId,
            q.installationDigest,
            object.payloadObjectId,
            object.objectVersion,
            sha256(object),
            admission.authorityDigest,
            request,
            bytes,
            sha256(bytes),
          ],
        );
        await client.query(
          `insert into control.evidence_kms_exchange
        (participant_id,privacy_domain_id,exchange_id,attempt_id,kind,challenge,request_bytes,request_digest)
        values($1,$2,$3,$3,'PREPARE',$4,$5,$6)`,
          [
            q.participantId,
            q.privacyDomainId,
            parsed.attemptId,
            request.challenge,
            bytes,
            sha256(bytes),
          ],
        );
        return this.select(client, parsed);
      },
    );
  }

  async readOriginal(socket: TLSSocket, input: unknown): Promise<EvidenceKmsAttempt> {
    const selector = parseEvidenceKms(evidenceKmsAttemptSelector, input);
    return withEvidenceKeyRecipient(
      this.pool,
      this.kernel,
      socket,
      selector.recipient,
      'READBACK',
      (client) => this.select(client, selector),
    );
  }

  /** Returns only after the dispatch commit. The runtime still owes authenticated
   * current provider admission before sending these original bytes. */
  async dispatch(socket: TLSSocket, input: unknown): Promise<EvidenceKmsAttempt> {
    const selector = parseEvidenceKms(evidenceKmsAttemptSelector, input);
    return this.transition(socket, selector, 'DISPATCHED');
  }
  async unknown(socket: TLSSocket, input: unknown): Promise<EvidenceKmsAttempt> {
    const selector = parseEvidenceKms(evidenceKmsAttemptSelector, input);
    return this.transition(socket, selector, 'UNKNOWN');
  }
  private transition(
    socket: TLSSocket,
    selector: EvidenceKmsAttemptSelector,
    next: 'DISPATCHED' | 'UNKNOWN',
  ) {
    const q = selector.recipient;
    return withEvidenceKeyRecipient(
      this.pool,
      this.kernel,
      socket,
      q,
      next === 'DISPATCHED' ? 'ENCRYPT' : 'READBACK',
      async (client, admission) => {
        assertEvidenceKeyAdmission(admission, client, q);
        const original = await this.select(client, selector);
        assertEvidenceKmsTransition(original.state, next);
        const changed = await client.query(
          `update control.evidence_kms_attempt set state=$4
          where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3 and state=$5 returning attempt_id`,
          [q.participantId, q.privacyDomainId, selector.attemptId, next, original.state],
        );
        if (changed.rowCount !== 1) rejectEvidenceKms('CONFLICT');
        await client.query(
          `update control.evidence_kms_exchange set state=$4 where participant_id=$1 and privacy_domain_id=$2
          and exchange_id=$3 and state in ('PREPARED','DISPATCHED','UNKNOWN')`,
          [q.participantId, q.privacyDomainId, selector.attemptId, next],
        );
        return this.select(client, selector);
      },
    );
  }

  /** Metadata is loaded inside real peer admission, then released for provider
   * I/O after this transaction commits. It conveys no ongoing material lease. */
  async installation(socket: TLSSocket, input: unknown, use: 'ENCRYPT' | 'DECRYPT' | 'READBACK') {
    const selector = parseEvidenceKms(evidenceKmsAttemptSelector, input);
    return withEvidenceKeyRecipient(
      this.pool,
      this.kernel,
      socket,
      selector.recipient,
      use,
      async (client, admission) => {
        await this.select(client, selector);
        return admission.installation.pins;
      },
    );
  }

  async createExchange(
    socket: TLSSocket,
    input: unknown,
    kind: 'STATUS' | 'READ_ATTEMPT' | 'UNWRAP',
    keyUse: 'NONE' | 'ENCRYPT' | 'DECRYPT' = 'NONE',
  ) {
    if (
      !['STATUS', 'READ_ATTEMPT', 'UNWRAP'].includes(kind) ||
      (kind === 'UNWRAP' ? !['ENCRYPT', 'DECRYPT'].includes(keyUse) : keyUse !== 'NONE')
    )
      rejectEvidenceKms('INVALID');
    const unwrap = kind === 'UNWRAP' ? parseEvidenceKms(evidenceKmsUnwrapInput, input) : undefined;
    if (unwrap && unwrap.use !== keyUse) rejectEvidenceKms('INVALID');
    const selector = unwrap
        ? { recipient: unwrap.recipient, attemptId: unwrap.attemptId }
        : parseEvidenceKms(evidenceKmsAttemptSelector, input),
      q = selector.recipient;
    const use = kind === 'READ_ATTEMPT' ? 'READBACK' : keyUse === 'DECRYPT' ? 'DECRYPT' : 'ENCRYPT';
    return withEvidenceKeyRecipient(
      this.pool,
      this.kernel,
      socket,
      q,
      use,
      async (client, admission) => {
        assertEvidenceKeyAdmission(admission, client, q);
        const original = await this.select(client, selector);
        const record = await client.query<{ key_id: string }>(
          `select key_id from control.evidence_wrapped_key
        where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3`,
          [q.participantId, q.privacyDomainId, selector.attemptId],
        );
        if (kind === 'UNWRAP' && (original.state !== 'PROVED' || record.rowCount !== 1))
          rejectEvidenceKms('UNKNOWN');
        // A caller key mismatch is a no-effect denial, before reserving the
        // one-time encryption lease or dispatching any provider request.
        if (unwrap && unwrap.keyId !== record.rows[0]?.key_id) rejectEvidenceKms('INTEGRITY');
        // A lost unwrap is reconciled before another material request. Reading a
        // record never retries the uncertain provider operation.
        const unresolved = `not exists(select 1 from control.evidence_kms_exchange done
        where done.participant_id=e.participant_id and done.privacy_domain_id=e.privacy_domain_id and done.attempt_id=e.attempt_id
        and done.kind='READ_ATTEMPT' and done.state='PROVED' and openpc.evidence_kms_stored_outcome(done.receipt_bytes) in ('1','2')
        and convert_from(done.request_bytes,'UTF8')::jsonb->>'readExchangeId'=e.exchange_id::text
        and convert_from(done.request_bytes,'UTF8')::jsonb->>'readRequestDigest'=e.request_digest)`;
        if (kind === 'UNWRAP') {
          const pending = await client.query(
            `select 1 from control.evidence_kms_exchange e where participant_id=$1
          and privacy_domain_id=$2 and attempt_id=$3 and kind='UNWRAP' and
          ((state in ('PREPARED','DISPATCHED','UNKNOWN') and ${unresolved}) or
           ($4='ENCRYPT' and convert_from(request_bytes,'UTF8')::jsonb->>'keyUse'='ENCRYPT'))`,
            [q.participantId, q.privacyDomainId, selector.attemptId, keyUse],
          );
          if (pending.rowCount) rejectEvidenceKms('UNKNOWN');
        }
        let readExchangeId: string | undefined, readRequestDigest: string | undefined;
        if (kind === 'READ_ATTEMPT') {
          const pending = await client.query<{ exchange_id: string; request_digest: string }>(
            `select exchange_id,request_digest
          from control.evidence_kms_exchange e where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3
          and kind='UNWRAP' and state in ('PREPARED','DISPATCHED','UNKNOWN') and ${unresolved} order by exchange_id limit 1`,
            [q.participantId, q.privacyDomainId, selector.attemptId],
          );
          readExchangeId = pending.rows[0]?.exchange_id ?? selector.attemptId;
          readRequestDigest = pending.rows[0]?.request_digest ?? original.requestDigest;
        }
        const exchangeId = localOperationId(),
          challenge = randomBytes(32).toString('hex');
        const request = {
          operation: kind,
          exchangeId,
          attemptId: selector.attemptId,
          recipient: q,
          originalRequestDigest: original.requestDigest,
          objectIntentDigest: original.objectIntentDigest,
          keyId: record.rows[0]?.key_id ?? evidenceKmsAbsentDigest,
          keyUse,
          challenge,
          ...(kind === 'READ_ATTEMPT' ? { readExchangeId, readRequestDigest } : {}),
        };
        const bytes = Buffer.from(canonicalJson(request));
        await client.query(
          `insert into control.evidence_kms_exchange
        (participant_id,privacy_domain_id,exchange_id,attempt_id,kind,challenge,request_bytes,request_digest)
        values($1,$2,$3,$4,$5,$6,$7,$8)`,
          [
            q.participantId,
            q.privacyDomainId,
            exchangeId,
            selector.attemptId,
            kind,
            challenge,
            bytes,
            sha256(bytes),
          ],
        );
        return { exchangeId, bytes };
      },
    );
  }

  async dispatchExchange(socket: TLSSocket, input: unknown, exchangeId: string) {
    return this.changeExchange(socket, input, exchangeId, 'DISPATCHED');
  }
  async unknownExchange(socket: TLSSocket, input: unknown, exchangeId: string) {
    return this.changeExchange(socket, input, exchangeId, 'UNKNOWN');
  }
  private async changeExchange(
    socket: TLSSocket,
    input: unknown,
    exchangeId: string,
    next: 'DISPATCHED' | 'UNKNOWN',
  ) {
    const selector = parseEvidenceKms(evidenceKmsAttemptSelector, input),
      q = selector.recipient;
    const use = await withEvidenceKeyRecipient(
      this.pool,
      this.kernel,
      socket,
      q,
      'READBACK',
      async (client) => {
        await this.select(client, selector);
        const exchange = await this.exchange(client, selector, exchangeId);
        const request = JSON.parse(exchange.request_bytes.toString('utf8')) as { keyUse?: string };
        return next === 'UNKNOWN' || exchange.kind === 'READ_ATTEMPT'
          ? 'READBACK'
          : request.keyUse === 'DECRYPT'
            ? 'DECRYPT'
            : 'ENCRYPT';
      },
    );
    return withEvidenceKeyRecipient(this.pool, this.kernel, socket, q, use, async (client) => {
      await this.select(client, selector);
      const exchange = await this.exchange(client, selector, exchangeId);
      assertEvidenceKmsTransition(exchange.state, next);
      await client.query(
        `update control.evidence_kms_exchange set state=$4
        where participant_id=$1 and privacy_domain_id=$2 and exchange_id=$3`,
        [q.participantId, q.privacyDomainId, exchangeId, next],
      );
      return Buffer.from(exchange.request_bytes);
    });
  }
  private async exchange(
    client: PoolClient,
    selector: EvidenceKmsAttemptSelector,
    exchangeId: string,
  ) {
    const q = selector.recipient;
    const result = await client.query<{
      exchange_id: string;
      kind: 'PREPARE' | 'STATUS' | 'READ_ATTEMPT' | 'UNWRAP';
      challenge: string;
      request_bytes: Buffer;
      request_digest: string;
      state: EvidenceKmsAttemptState;
    }>(
      `select exchange_id,kind,challenge,
      request_bytes,request_digest,state from control.evidence_kms_exchange where participant_id=$1 and privacy_domain_id=$2
      and attempt_id=$3 and exchange_id=$4 for update`,
      [q.participantId, q.privacyDomainId, selector.attemptId, exchangeId],
    );
    if (result.rowCount !== 1) rejectEvidenceKms('UNAVAILABLE');
    const row = result.rows[0]!;
    if (sha256(row.request_bytes) !== row.request_digest) rejectEvidenceKms('INTEGRITY');
    return row;
  }

  /** Authentication and durable receipt attachment are one SQL transaction.
   * Local crypto is synchronous. Only ciphertext persistence may be asynchronous
   * under these fences, after owned DEK erasure; provider I/O stays outside. */
  async acceptExchange<T>(
    socket: TLSSocket,
    input: unknown,
    exchangeId: string,
    wire: Buffer,
    useMaterial?: (material: { keyId: string; bytes: Buffer; signal: AbortSignal }) => T,
    persistCiphertext?: EvidenceKmsCiphertextPersistence,
  ) {
    const selector = parseEvidenceKms(evidenceKmsAttemptSelector, input),
      q = selector.recipient;
    // Establish the requested operation from the durable exchange, not a caller
    // supplied key-use flag. Actual use re-enters the stronger current fence.
    const operation = await withEvidenceKeyRecipient(
      this.pool,
      this.kernel,
      socket,
      q,
      'READBACK',
      async (client) => {
        await this.select(client, selector);
        const exchange = await this.exchange(client, selector, exchangeId);
        const request = JSON.parse(exchange.request_bytes.toString('utf8')) as {
          keyUse?: 'ENCRYPT' | 'DECRYPT';
        };
        return exchange.kind === 'UNWRAP' ? request.keyUse : undefined;
      },
    );
    if (useMaterial && operation !== 'ENCRYPT' && operation !== 'DECRYPT')
      rejectEvidenceKms('SCOPE');
    if (
      (operation === 'ENCRYPT' && (!useMaterial || !persistCiphertext)) ||
      (operation !== 'ENCRYPT' && persistCiphertext)
    )
      rejectEvidenceKms('SCOPE');
    return withEvidenceKeyRecipient(
      this.pool,
      this.kernel,
      socket,
      q,
      operation ?? 'READBACK',
      async (client, admission) => {
        assertEvidenceKeyAdmission(admission, client, q);
        const original = await this.select(client, selector),
          exchange = await this.exchange(client, selector, exchangeId);
        if (exchange.state !== 'DISPATCHED' && exchange.state !== 'UNKNOWN')
          rejectEvidenceKms('CONFLICT');
        const request = JSON.parse(exchange.request_bytes.toString('utf8')) as {
          keyId?: string;
          keyUse?: 'NONE' | 'ENCRYPT' | 'DECRYPT';
        };
        const floors = await client.query<{ sequence: string; floor: string }>(
          `select coalesce(max(e.provider_sequence),1)::text sequence,
        coalesce(max(e.recovery_floor),1)::text floor from control.evidence_kms_exchange e
        join control.evidence_kms_attempt a using(participant_id,privacy_domain_id,attempt_id)
        join control.evidence_kms_installation i using(participant_id,privacy_domain_id,installation_digest)
        where e.participant_id=$1 and e.privacy_domain_id=$2 and i.pins->>'providerId'=$3
        and i.pins->>'providerKeyId'=$4 and i.pins->>'providerKeyVersion'=$5`,
          [
            q.participantId,
            q.privacyDomainId,
            admission.installation.pins.providerId,
            admission.installation.pins.providerKeyId,
            admission.installation.pins.providerKeyVersion,
          ],
        );
        const expected: EvidenceKmsExpectedResponse = {
          operation: exchange.kind,
          attemptId: selector.attemptId,
          exchangeId,
          requestDigest: exchange.request_digest,
          originalRequestDigest: original.requestDigest,
          objectIntentDigest: original.objectIntentDigest,
          challenge: exchange.challenge,
          keyId: request.keyId ?? evidenceKmsAbsentDigest,
          keyUse: request.keyUse ?? 'NONE',
          nowMs: Date.now(),
          minimumSequence: floors.rows[0]!.sequence,
          minimumRecoveryFloor: floors.rows[0]!.floor,
        };
        const verified = verifyEvidenceKmsResponse(wire, admission.installation.pins, expected);
        try {
          const receiptBytes = evidenceKmsReceiptBytes(verified);
          await client.query(
            `update control.evidence_kms_exchange set state='PROVED',receipt_bytes=$4,receipt_digest=$5,
          provider_sequence=$6,recovery_floor=$7 where participant_id=$1 and privacy_domain_id=$2 and exchange_id=$3`,
            [
              q.participantId,
              q.privacyDomainId,
              exchangeId,
              receiptBytes,
              sha256(receiptBytes),
              verified.receipt.providerSequence,
              verified.receipt.recoveryFloor,
            ],
          );
          if (exchange.kind === 'PREPARE' || exchange.kind === 'READ_ATTEMPT') {
            if (verified.receipt.outcome === 'PROVED') {
              const record = verified.response.record;
              await client.query(
                `insert into control.evidence_wrapped_key(participant_id,privacy_domain_id,attempt_id,key_id,record_bytes,record_cose)
              values($1,$2,$3,$4,$5,$6) on conflict do nothing`,
                [
                  q.participantId,
                  q.privacyDomainId,
                  selector.attemptId,
                  verified.receipt.keyId,
                  record.payload,
                  record.cose,
                ],
              );
              const stored = await client.query<{ record_bytes: Buffer; record_cose: Buffer }>(
                `select record_bytes,record_cose from control.evidence_wrapped_key
              where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3`,
                [q.participantId, q.privacyDomainId, selector.attemptId],
              );
              if (
                stored.rowCount !== 1 ||
                !stored.rows[0]!.record_bytes.equals(record.payload) ||
                !stored.rows[0]!.record_cose.equals(record.cose)
              )
                rejectEvidenceKms('INTEGRITY');
            }
            if (original.state === 'DISPATCHED' || original.state === 'UNKNOWN') {
              const next =
                verified.receipt.outcome === 'PROVED'
                  ? 'PROVED'
                  : verified.receipt.outcome === 'REJECTED'
                    ? 'REJECTED'
                    : 'UNKNOWN';
              await client.query(
                `update control.evidence_kms_attempt set state=$4,result_receipt_bytes=$5,result_receipt_digest=$6
              where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3`,
                [
                  q.participantId,
                  q.privacyDomainId,
                  selector.attemptId,
                  next,
                  next === 'UNKNOWN' ? null : receiptBytes,
                  next === 'UNKNOWN' ? null : sha256(receiptBytes),
                ],
              );
            }
          }
          let result: T | undefined;
          if (useMaterial && verified.receipt.outcome === 'PROVED') {
            const deadline = Math.min(
              Date.now() + 1000,
              verified.receipt.validUntilMs,
              verified.recovery.validUntilMs,
              admission.installation.pins.validUntilMs,
            );
            result = await completeEvidenceKmsMaterial(
              {
                client,
                original,
                selector,
                exchangeId,
                keyId: verified.receipt.keyId,
                material: verified.response.material,
                wire,
                leaseUntilMs: deadline,
                receiptUntilMs: Math.min(
                  verified.receipt.validUntilMs,
                  verified.recovery.validUntilMs,
                ),
              },
              useMaterial,
              persistCiphertext,
            );
          }
          return { receipt: verified.receipt, result };
        } finally {
          verified.response.material.fill(0);
          wire.fill(0);
        }
      },
    );
  }
}

export function assertEvidenceKmsReplay(
  attempt: EvidenceKmsAttempt,
  input: EvidenceKmsPrepareInput,
): void {
  assertEvidenceKmsOriginal(attempt, input);
  const parsed = inspectEvidenceKmsPrepareRequest(attempt.requestBytes);
  const original = {
    recipient: parsed.recipient,
    attemptId: parsed.attemptId,
    objectIntent: parsed.objectIntent,
  };
  if (canonicalJson(original) !== canonicalJson(input)) rejectEvidenceKms('CONFLICT');
}
