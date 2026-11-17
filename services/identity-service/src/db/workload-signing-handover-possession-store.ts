import { randomBytes } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import { signingRotationActions } from '../../../../packages/security-kernel/src/signing-operations.js';
import {
  handoverPossessionGenerationRequestSchema,
  handoverPossessionGenerationSchema,
  handoverPossessionGenerationDigest,
  handoverPossessionMaximumLifetimeNs,
  prepareHandoverPossessionAttempt,
  handoverPossessionAttemptBytes,
  handoverPossessionAttemptDigest,
  type HandoverPossessionGenerationRequest,
  type HandoverPossessionAttempt,
} from '../domain/workload-signing-handover-possession.js';
import { localOperationId } from '../domain/local-operation-id.js';
import { runScopedTransaction } from './scoped-transaction.js';
import { captureWorkloadSigningHandoverSource } from './workload-signing-handover-source.js';
import { loadWorkloadSigningHandoverAttempt } from './workload-signing-handover-store.js';
import { readWorkloadSigningHandoverObservationsInTransaction } from './workload-signing-handover-observations.js';
import {
  loadWorkloadSigningHandoverGeneration,
  authenticateHandoverGeneration,
  handoverGenerationColumns,
  assertHandoverGenerationPreparationsStable,
  type HandoverGenerationRow,
} from './workload-signing-handover-generation-reader.js';
import {
  canonical,
  hash,
  tagged,
  idempotency,
  providerId,
  fail,
  admitMaker,
  retained,
  snapshot,
  type WorkloadSigningHandoverScope,
} from './workload-signing-handover-custody.js';

async function generationAttempts(
  client: PoolClient,
  scope: WorkloadSigningHandoverScope,
  row: HandoverGenerationRow,
) {
  const ids = await client.query<{ attemptId: string }>(
    `select attempt_id::text as "attemptId" from control.workload_signing_handover_attempt where participant_id=$1 and privacy_domain_id=$2 and handover_id=$3 and generation_id=$4 and stage='POSSESSION' order by predecessor_fingerprint`,
    [scope.participantId, scope.privacyDomainId, row.handoverId, row.generationId],
  );
  if (ids.rowCount !== row.document.keys.length) fail('CORRUPT');
  const attempts: HandoverPossessionAttempt[] = [];
  for (const { attemptId } of ids.rows) {
    const loaded = await loadWorkloadSigningHandoverAttempt(client, scope, attemptId);
    if (!('stage' in loaded.attempt) || loaded.attempt.generationId !== row.generationId)
      fail('CORRUPT');
    attempts.push(loaded.attempt);
  }
  return attempts;
}
async function generationView(
  client: PoolClient,
  scope: WorkloadSigningHandoverScope,
  row: HandoverGenerationRow,
) {
  const selected = await client.query<{ nowNs: string; superseded: boolean }>(
    `select (floor(extract(epoch from clock_timestamp())*1000000)*1000)::numeric(20,0)::text as "nowNs",exists(select 1 from control.workload_signing_handover_generation where participant_id=$1 and privacy_domain_id=$2 and supersedes_generation_id=$3) as superseded`,
    [scope.participantId, scope.privacyDomainId, row.generationId],
  );
  const now = selected.rows[0]!;
  return {
    handoverId: row.handoverId,
    generationId: row.generationId,
    generationDigest: tagged(row.documentDigest),
    requestDigest: tagged(row.requestDigest),
    issuedAtNs: row.document.issuedAtNs,
    expiresAtNs: row.document.expiresAtNs,
    supersedesGenerationId: row.supersedesGenerationId,
    state: now.superseded
      ? ('SUPERSEDED' as const)
      : BigInt(now.nowNs) >= BigInt(row.document.expiresAtNs)
        ? ('EXPIRED' as const)
        : ('PROVING' as const),
    keyCount: row.document.keys.length,
    attempts: await generationAttempts(client, scope, row),
  };
}

/** One complete, immutable generation and all its proof commands commit before
 * provider I/O. Expired settled proof may be refreshed only by explicit intent. */
export async function createWorkloadSigningHandoverPossessionGeneration(
  pool: Pool,
  scope: WorkloadSigningHandoverScope,
  handoverId: string,
  input: HandoverPossessionGenerationRequest,
  idempotencyKey: string,
  configuredProviders: { receipt: string; envelope: string },
) {
  const request = handoverPossessionGenerationRequestSchema.parse(input),
    key = idempotency.parse(idempotencyKey);
  const requestCanonical = canonical(request),
    requestDigest = hash(
      'pc.identity.workload-signing-handover.possession-generation-request.v1',
      requestCanonical,
    );
  return runScopedTransaction(
    pool,
    { ...scope, actionIntentId: signingRotationActions.create, isolation: 'SERIALIZABLE' },
    localOperationId,
    async (client, operationId) => {
      await admitMaker(client, scope);
      const owner = await retained(client, scope, handoverId);
      const replay = await client.query<HandoverGenerationRow>(
        `select ${handoverGenerationColumns} from control.workload_signing_handover_generation where participant_id=$1 and privacy_domain_id=$2 and maker_principal_id=$3 and idempotency_key=$4`,
        [scope.participantId, scope.privacyDomainId, scope.authority.principalId, key],
      );
      if (replay.rowCount === 1) {
        const saved = authenticateHandoverGeneration(replay.rows[0]!);
        if (
          saved.handoverId !== handoverId ||
          !saved.requestCanonical.equals(requestCanonical) ||
          !saved.requestDigest.equals(requestDigest)
        )
          fail('CONFLICT');
        return generationView(
          client,
          scope,
          await loadWorkloadSigningHandoverGeneration(client, scope, saved.generationId),
        );
      }
      const current = await captureWorkloadSigningHandoverSource(client, scope, owner.request);
      if (!canonical(current.document).equals(owner.sourceCanonical)) fail('CONFLICT');
      const issuedAtNs = current.recordedAtNs.toString();
      if (request.supersedesGenerationId === null) {
        const existing = await client.query(
          `select 1 from control.workload_signing_handover_generation where participant_id=$1 and privacy_domain_id=$2 and handover_id=$3`,
          [scope.participantId, scope.privacyDomainId, handoverId],
        );
        if (existing.rowCount !== 0) fail('CONFLICT');
      } else {
        const parent = await loadWorkloadSigningHandoverGeneration(
          client,
          scope,
          request.supersedesGenerationId,
        );
        if (
          parent.handoverId !== handoverId ||
          parent.makerPrincipalId !== scope.authority.principalId ||
          BigInt(issuedAtNs) < BigInt(parent.document.expiresAtNs)
        )
          fail('CONFLICT');
        const successor = await client.query(
          `select 1 from control.workload_signing_handover_generation where participant_id=$1 and privacy_domain_id=$2 and supersedes_generation_id=$3`,
          [scope.participantId, scope.privacyDomainId, parent.generationId],
        );
        if (successor.rowCount !== 0) fail('CONFLICT');
        for (const attempt of await generationAttempts(client, scope, parent)) {
          const dispatch = await client.query<{ dispatchId: string }>(
            `select dispatch_id::text as "dispatchId" from control.workload_signing_handover_dispatch where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3`,
            [scope.participantId, scope.privacyDomainId, attempt.request.attemptId],
          );
          if (dispatch.rowCount !== 1) fail('CONFLICT');
          const observed = await readWorkloadSigningHandoverObservationsInTransaction(
            client,
            scope,
            attempt.request.attemptId,
            dispatch.rows[0]!.dispatchId,
          );
          if (observed.state !== 'OBSERVED' || observed.firstObservation?.outcome !== 'SUCCEEDED')
            fail('CONFLICT');
        }
      }
      const prepared = await client.query<{ attemptId: string; dispatchId: string }>(
        `select a.attempt_id::text as "attemptId",d.dispatch_id::text as "dispatchId"
      from control.workload_signing_handover_attempt a join control.workload_signing_handover_dispatch d on d.participant_id=a.participant_id and d.privacy_domain_id=a.privacy_domain_id and d.attempt_id=a.attempt_id
      where a.participant_id=$1 and a.privacy_domain_id=$2 and a.handover_id=$3 and a.stage='PREPARATION' order by a.predecessor_fingerprint`,
        [scope.participantId, scope.privacyDomainId, handoverId],
      );
      if (prepared.rowCount !== owner.request.replacements.length) fail('CONFLICT');
      const keys = [];
      let expires = BigInt(issuedAtNs) + handoverPossessionMaximumLifetimeNs;
      if (
        current.document.issuer.credentialValidUntilNs !== null &&
        BigInt(current.document.issuer.credentialValidUntilNs) < expires
      )
        expires = BigInt(current.document.issuer.credentialValidUntilNs);
      for (const preparedKey of prepared.rows) {
        const command = await loadWorkloadSigningHandoverAttempt(
          client,
          scope,
          preparedKey.attemptId,
        );
        if ('stage' in command.attempt) fail('CORRUPT');
        const configured =
          command.attempt.signerRole === 'IDENTITY_ENVELOPE'
            ? configuredProviders.envelope
            : configuredProviders.receipt;
        if (command.binding.providerId !== providerId.parse(configured)) fail('CONFLICT');
        const observed = await readWorkloadSigningHandoverObservationsInTransaction(
          client,
          scope,
          preparedKey.attemptId,
          preparedKey.dispatchId,
        );
        if (
          observed.state !== 'OBSERVED' ||
          observed.firstObservation?.outcome !== 'SUCCEEDED' ||
          !observed.firstObservation.descriptor
        )
          fail('CONFLICT');
        if (
          !owner.request.replacements.some((replacement) =>
            canonical(replacement).equals(canonical(command.binding.replacement)),
          )
        )
          fail('CORRUPT');
        if (BigInt(observed.firstObservation.descriptor.validUntilNs) < expires)
          expires = BigInt(observed.firstObservation.descriptor.validUntilNs);
        keys.push({
          binding: command.binding,
          attempt: command.attempt,
          observation: observed.firstObservation,
        });
      }
      const generationId = localOperationId();
      const document = handoverPossessionGenerationSchema.parse({
        schema: 'pc.identity.workload-signing-handover.possession-generation.v1',
        participantId: scope.participantId,
        privacyDomainId: scope.privacyDomainId,
        environmentId: scope.environmentId,
        handoverId,
        sourceDigest: tagged(owner.sourceDigest),
        generationId,
        operationId,
        makerPrincipalId: scope.authority.principalId,
        supersedesGenerationId: request.supersedesGenerationId,
        issuedAtNs,
        expiresAtNs: expires.toString(),
        issuer: current.document.issuer,
        keys,
      });
      await assertHandoverGenerationPreparationsStable(client, scope, document);
      const authority = await snapshot(client, scope, operationId, owner.source);
      await client.query(
        `insert into control.workload_signing_handover_generation(participant_id,privacy_domain_id,handover_id,generation_id,operation_id,maker_principal_id,idempotency_key,supersedes_generation_id,request,request_canonical,request_digest,document,document_canonical,document_digest,authority_snapshot,authority_snapshot_digest,recorded_at_ns)
      values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,floor(extract(epoch from clock_timestamp())*1000000)*1000)`,
        [
          scope.participantId,
          scope.privacyDomainId,
          handoverId,
          generationId,
          operationId,
          scope.authority.principalId,
          key,
          request.supersedesGenerationId,
          request,
          requestCanonical,
          requestDigest,
          document,
          canonical(document),
          Buffer.from(handoverPossessionGenerationDigest(document).slice(7), 'hex'),
          authority.bytes,
          authority.digest,
        ],
      );
      for (const preparedKey of document.keys) {
        const attempt = prepareHandoverPossessionAttempt(
          document,
          preparedKey.binding.replacement.oldFingerprint,
          {
            operationId,
            attemptId: localOperationId(),
            challengeNonceHex: randomBytes(32).toString('hex'),
          },
        );
        await client.query(
          `insert into control.workload_signing_handover_attempt(participant_id,privacy_domain_id,handover_id,attempt_id,operation_id,maker_principal_id,predecessor_fingerprint,provider_id,stage,generation_id,preparation_attempt_id,binding,binding_canonical,binding_digest,attempt,attempt_canonical,attempt_digest,authority_snapshot,authority_snapshot_digest,recorded_at_ns)
        values($1,$2,$3,$4,$5,$6,$7,$8,'POSSESSION',$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,floor(extract(epoch from clock_timestamp())*1000000)*1000)`,
          [
            scope.participantId,
            scope.privacyDomainId,
            handoverId,
            attempt.request.attemptId,
            operationId,
            scope.authority.principalId,
            attempt.predecessorFingerprint,
            attempt.providerId,
            generationId,
            attempt.preparationAttemptId,
            preparedKey.binding,
            canonical(preparedKey.binding),
            Buffer.from(attempt.bindingDigest.slice(7), 'hex'),
            attempt,
            handoverPossessionAttemptBytes(attempt),
            Buffer.from(handoverPossessionAttemptDigest(attempt).slice(7), 'hex'),
            authority.bytes,
            authority.digest,
          ],
        );
      }
      return generationView(
        client,
        scope,
        await loadWorkloadSigningHandoverGeneration(client, scope, generationId),
      );
    },
  );
}

export async function readWorkloadSigningHandoverPossessionGeneration(
  pool: Pool,
  scope: WorkloadSigningHandoverScope,
  generationId: string,
) {
  return runScopedTransaction(
    pool,
    { ...scope, actionIntentId: signingRotationActions.create, isolation: 'SERIALIZABLE' },
    localOperationId,
    async (client) => {
      await admitMaker(client, scope);
      const row = await loadWorkloadSigningHandoverGeneration(client, scope, generationId);
      await retained(client, scope, row.handoverId);
      return generationView(client, scope, row);
    },
  );
}
