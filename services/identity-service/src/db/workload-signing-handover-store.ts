import {
  canonical,
  hash,
  tagged,
  idempotency,
  providerId,
  columns,
  fail,
  authenticate,
  view,
  admitMaker,
  retained,
  snapshot,
  type RequestRow,
  type WorkloadSigningHandoverScope,
  type WorkloadSigningHandoverAttemptScope,
} from './workload-signing-handover-custody.js';
export { WorkloadSigningHandoverStoreError } from './workload-signing-handover-custody.js';
export type {
  WorkloadSigningHandoverScope,
  WorkloadSigningHandoverAttemptScope,
} from './workload-signing-handover-custody.js';
import type { Pool, PoolClient } from 'pg';
import { z } from 'zod';
import { signingRotationActions } from '../../../../packages/security-kernel/src/signing-operations.js';
import {
  workloadSigningHandoverRequestSchema,
  type WorkloadSigningHandoverRequest,
} from '../contracts/workload-signing-handover.js';
import {
  handoverProviderBindingSchema,
  prepareHandoverProviderAttempt,
  handoverPreparationAttemptBytes,
  handoverPreparationAttemptDigest,
  type HandoverProviderBinding,
  type HandoverPreparationAttempt,
} from '../domain/workload-signing-handover-provider.js';
import { localOperationId } from '../domain/local-operation-id.js';
import { runScopedTransaction } from './scoped-transaction.js';
import { captureWorkloadSigningHandoverSource } from './workload-signing-handover-source.js';
import {
  prepareHandoverPossessionAttempt,
  handoverProviderAttemptBytes,
  handoverProviderAttemptDigest,
  type HandoverProviderAttempt,
} from '../domain/workload-signing-handover-possession.js';
import {
  loadWorkloadSigningHandoverGeneration,
  assertHandoverGenerationCanDispatch,
} from './workload-signing-handover-generation-reader.js';

/** Record the authenticated source once. Exact replay reads the original intent
 * under current maker authority; it never recaptures or overwrites that source. */
export async function createWorkloadSigningHandover(
  pool: Pool,
  scope: WorkloadSigningHandoverScope,
  input: WorkloadSigningHandoverRequest,
  idempotencyKey: string,
) {
  const request = workloadSigningHandoverRequestSchema.parse(input);
  const key = idempotency.parse(idempotencyKey);
  if (request.environmentId !== scope.environmentId) fail('DENIED');
  const requestCanonical = canonical(request);
  const requestDigest = hash('pc.identity.workload-signing-handover.request.v1', requestCanonical);
  return runScopedTransaction(
    pool,
    { ...scope, actionIntentId: signingRotationActions.create, isolation: 'SERIALIZABLE' },
    localOperationId,
    async (client, operationId) => {
      await admitMaker(client, scope);
      const replay = await client.query<RequestRow>(
        `select ${columns} from control.workload_signing_handover
       where participant_id=$1 and privacy_domain_id=$2 and maker_principal_id=$3 and idempotency_key=$4`,
        [scope.participantId, scope.privacyDomainId, scope.authority.principalId, key],
      );
      if (replay.rowCount === 1) {
        const row = authenticate(replay.rows[0]!);
        if (
          !row.requestDigest.equals(requestDigest) ||
          !row.requestCanonical.equals(requestCanonical)
        )
          fail('CONFLICT');
        return view(row);
      }
      const source = await captureWorkloadSigningHandoverSource(client, scope, request);
      const sourceCanonical = canonical(source.document);
      const sourceDigest = hash('pc.identity.workload-signing-handover.source.v1', sourceCanonical);
      const authority = await snapshot(client, scope, operationId, source.document);
      const handoverId = localOperationId();
      await client.query(
        `insert into control.workload_signing_handover(participant_id,privacy_domain_id,handover_id,operation_id,
        maker_principal_id,idempotency_key,predecessor_credential_id,successor_credential_id,workload_principal_id,environment_id,
        request,request_canonical,request_digest,source,source_canonical,source_digest,authority_snapshot,authority_snapshot_digest,recorded_at_ns)
        values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,floor(extract(epoch from clock_timestamp())*1000000)*1000)`,
        [
          scope.participantId,
          scope.privacyDomainId,
          handoverId,
          operationId,
          scope.authority.principalId,
          key,
          request.predecessorCredentialId,
          request.successorCredentialId,
          source.document.issuer.workloadPrincipalId,
          scope.environmentId,
          request,
          requestCanonical,
          requestDigest,
          source.document,
          sourceCanonical,
          sourceDigest,
          authority.bytes,
          authority.digest,
        ],
      );
      return view(await retained(client, scope, handoverId));
    },
  );
}

/** Internal custody read; the public route must choose and verify its read
 * permission separately. This preparation path requires the original maker. */
export async function readWorkloadSigningHandover(
  pool: Pool,
  scope: WorkloadSigningHandoverScope,
  handoverId: string,
) {
  return runScopedTransaction(
    pool,
    { ...scope, actionIntentId: signingRotationActions.create, isolation: 'SERIALIZABLE' },
    localOperationId,
    async (client) => {
      await admitMaker(client, scope);
      return view(await retained(client, scope, handoverId));
    },
  );
}

/** Persist exact commands only. No provider perform, lookup or signing grant. */
export async function recordWorkloadSigningHandoverAttempt(
  pool: Pool,
  scope: WorkloadSigningHandoverScope,
  handoverId: string,
  predecessorFingerprint: string,
  configuredProviders: { receipt: string; envelope: string },
): Promise<HandoverPreparationAttempt> {
  return runScopedTransaction(
    pool,
    { ...scope, actionIntentId: signingRotationActions.create, isolation: 'SERIALIZABLE' },
    localOperationId,
    async (client, operationId) => {
      await admitMaker(client, scope);
      const row = await retained(client, scope, handoverId);
      const source = await captureWorkloadSigningHandoverSource(client, scope, row.request);
      if (!canonical(source.document).equals(row.sourceCanonical)) fail('CONFLICT');
      const replacement = row.request.replacements.find(
        (key) => key.oldFingerprint === predecessorFingerprint,
      );
      if (!replacement) fail('NOT_FOUND');
      const binding: HandoverProviderBinding = handoverProviderBindingSchema.parse({
        participantId: scope.participantId,
        privacyDomainId: scope.privacyDomainId,
        environmentId: scope.environmentId,
        handoverId,
        sourceDigest: tagged(row.sourceDigest),
        successorCredentialId: row.source.issuer.workloadCredentialId,
        successorCredentialEpoch: row.source.issuer.workloadCredentialEpoch,
        participantEpoch: row.source.issuer.workloadParticipantEpoch,
        principalEpoch: row.source.issuer.workloadPrincipalEpoch,
        replacement,
        providerId: providerId.parse(
          replacement.signerRole === 'IDENTITY_ENVELOPE'
            ? configuredProviders.envelope
            : configuredProviders.receipt,
        ),
      });
      const existing = await client.query<{
        attempt: HandoverPreparationAttempt;
        binding: HandoverProviderBinding;
        bindingCanonical: Buffer;
        bindingDigest: Buffer;
        attemptCanonical: Buffer;
        attemptDigest: Buffer;
      }>(
        `select attempt,binding,binding_canonical as "bindingCanonical",binding_digest as "bindingDigest",attempt_canonical as "attemptCanonical",attempt_digest as "attemptDigest" from control.workload_signing_handover_attempt
         where participant_id=$1 and privacy_domain_id=$2 and handover_id=$3 and predecessor_fingerprint=$4 and stage='PREPARATION'`,
        [scope.participantId, scope.privacyDomainId, handoverId, predecessorFingerprint],
      );
      if (existing.rowCount === 1) {
        const saved = existing.rows[0]!;
        const expected = prepareHandoverProviderAttempt(binding, {
          operationId: saved.attempt.request.operationId,
          attemptId: saved.attempt.request.attemptId,
        });
        if (
          !handoverPreparationAttemptBytes(saved.attempt).equals(saved.attemptCanonical) ||
          !canonical(saved.binding).equals(saved.bindingCanonical) ||
          !canonical(binding).equals(saved.bindingCanonical) ||
          expected.bindingDigest !== tagged(saved.bindingDigest) ||
          !handoverPreparationAttemptBytes(expected).equals(saved.attemptCanonical) ||
          handoverPreparationAttemptDigest(expected) !== tagged(saved.attemptDigest)
        )
          fail('CONFLICT');
        return expected;
      }
      const attempt = prepareHandoverProviderAttempt(binding, {
        operationId,
        attemptId: localOperationId(),
      });
      const authority = await snapshot(client, scope, operationId, row.source);
      await client.query(
        `insert into control.workload_signing_handover_attempt(participant_id,privacy_domain_id,handover_id,
        attempt_id,operation_id,maker_principal_id,predecessor_fingerprint,provider_id,binding,binding_canonical,binding_digest,
        attempt,attempt_canonical,attempt_digest,authority_snapshot,authority_snapshot_digest,recorded_at_ns)
        values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,floor(extract(epoch from clock_timestamp())*1000000)*1000)`,
        [
          scope.participantId,
          scope.privacyDomainId,
          handoverId,
          attempt.request.attemptId,
          operationId,
          scope.authority.principalId,
          predecessorFingerprint,
          binding.providerId,
          binding,
          canonical(binding),
          Buffer.from(attempt.bindingDigest.slice(7), 'hex'),
          attempt,
          handoverPreparationAttemptBytes(attempt),
          Buffer.from(handoverPreparationAttemptDigest(attempt).slice(7), 'hex'),
          authority.bytes,
          authority.digest,
        ],
      );
      return attempt;
    },
  );
}

/** Authenticate retained commands without reinterpreting their original caller,
 * operation or provider. Observation recovery does not need current maker authority. */
export async function loadWorkloadSigningHandoverAttempt(
  client: PoolClient,
  scope: WorkloadSigningHandoverAttemptScope,
  attemptId: string,
) {
  const selected = await client.query<{
    handoverId: string;
    operationId: string;
    stage: 'PREPARATION' | 'POSSESSION';
    generationId: string | null;
    preparationAttemptId: string | null;
    binding: HandoverProviderBinding;
    attempt: HandoverProviderAttempt;
    bindingCanonical: Buffer;
    bindingDigest: Buffer;
    attemptCanonical: Buffer;
    attemptDigest: Buffer;
  }>(
    `select handover_id::text as "handoverId",operation_id::text as "operationId",stage,generation_id::text as "generationId",preparation_attempt_id::text as "preparationAttemptId",binding,attempt,binding_canonical as "bindingCanonical",
     binding_digest as "bindingDigest",attempt_canonical as "attemptCanonical",attempt_digest as "attemptDigest"
     from control.workload_signing_handover_attempt
     where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3`,
    [scope.participantId, scope.privacyDomainId, z.uuidv7().parse(attemptId)],
  );
  if (selected.rowCount !== 1) fail('NOT_FOUND');
  const row = selected.rows[0]!;
  const binding = handoverProviderBindingSchema.parse(row.binding);
  let expected: HandoverProviderAttempt;
  let generation:
    Awaited<ReturnType<typeof loadWorkloadSigningHandoverGeneration>>['document'] | undefined;
  if (row.stage === 'POSSESSION') {
    if (!row.generationId || !row.preparationAttemptId || !('stage' in row.attempt))
      fail('CORRUPT');
    generation = (await loadWorkloadSigningHandoverGeneration(client, scope, row.generationId))
      .document;
    const key = generation.keys.find(
      (key) => key.binding.replacement.oldFingerprint === binding.replacement.oldFingerprint,
    );
    if (
      !key ||
      !canonical(key.binding).equals(row.bindingCanonical) ||
      generation.operationId !== row.operationId ||
      row.attempt.preparationAttemptId !== row.preparationAttemptId
    )
      fail('CORRUPT');
    expected = prepareHandoverPossessionAttempt(generation, binding.replacement.oldFingerprint, {
      operationId: row.operationId,
      attemptId,
      challengeNonceHex: row.attempt.challengeNonceHex,
    });
  } else {
    if (
      row.stage !== 'PREPARATION' ||
      row.generationId !== null ||
      row.preparationAttemptId !== null ||
      'stage' in row.attempt
    )
      fail('CORRUPT');
    expected = prepareHandoverProviderAttempt(binding, { operationId: row.operationId, attemptId });
  }
  if (
    binding.participantId !== scope.participantId ||
    binding.privacyDomainId !== scope.privacyDomainId ||
    binding.handoverId !== row.handoverId ||
    !canonical(binding).equals(row.bindingCanonical) ||
    expected.bindingDigest !== tagged(row.bindingDigest) ||
    row.attempt.request.operationId !== row.operationId ||
    !handoverProviderAttemptBytes(row.attempt).equals(row.attemptCanonical) ||
    !handoverProviderAttemptBytes(expected).equals(row.attemptCanonical) ||
    handoverProviderAttemptDigest(expected) !== tagged(row.attemptDigest)
  )
    fail('CORRUPT');
  return {
    handoverId: row.handoverId,
    binding,
    attempt: expected,
    attemptDigest: row.attemptDigest,
    generation,
  };
}

/** The unique immutable claim is committed before external I/O. A retained
 * claim permits lookup only, including when its original dispatch never ran. */
export async function claimWorkloadSigningHandoverDispatch(
  pool: Pool,
  scope: WorkloadSigningHandoverScope,
  attemptId: string,
  configuredProviders: { receipt: string; envelope: string },
) {
  return runScopedTransaction(
    pool,
    { ...scope, actionIntentId: signingRotationActions.create, isolation: 'SERIALIZABLE' },
    localOperationId,
    async (client, operationId) => {
      await admitMaker(client, scope);
      const command = await loadWorkloadSigningHandoverAttempt(client, scope, attemptId);
      const row = await retained(client, scope, command.handoverId);
      const expectedProvider =
        command.attempt.signerRole === 'IDENTITY_ENVELOPE'
          ? configuredProviders.envelope
          : configuredProviders.receipt;
      if (command.binding.providerId !== providerId.parse(expectedProvider)) fail('CONFLICT');
      const saved = await client.query<{
        dispatchId: string;
        attemptDigest: Buffer;
        sourceDigest: Buffer;
      }>(
        `select dispatch_id::text as "dispatchId",attempt_digest as "attemptDigest",source_digest as "sourceDigest"
         from control.workload_signing_handover_dispatch
         where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3`,
        [scope.participantId, scope.privacyDomainId, attemptId],
      );
      if (saved.rowCount === 1) {
        const dispatch = saved.rows[0]!;
        if (
          !dispatch.attemptDigest.equals(command.attemptDigest) ||
          !dispatch.sourceDigest.equals(row.sourceDigest)
        )
          fail('CORRUPT');
        return { ...command, dispatchId: dispatch.dispatchId, dispatch: false };
      }
      const currentSource = await captureWorkloadSigningHandoverSource(client, scope, row.request);
      if (!canonical(currentSource.document).equals(row.sourceCanonical)) fail('CONFLICT');
      if (command.generation)
        await assertHandoverGenerationCanDispatch(client, scope, command.generation);
      const authority = await snapshot(client, scope, operationId, row.source);
      const dispatchId = localOperationId();
      await client.query(
        `insert into control.workload_signing_handover_dispatch
         (participant_id,privacy_domain_id,handover_id,attempt_id,dispatch_id,operation_id,maker_principal_id,
          attempt_digest,source_digest,authority_snapshot,authority_snapshot_digest,recorded_at_ns)
         values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,floor(extract(epoch from clock_timestamp())*1000000)*1000)`,
        [
          scope.participantId,
          scope.privacyDomainId,
          command.handoverId,
          attemptId,
          dispatchId,
          operationId,
          scope.authority.principalId,
          command.attemptDigest,
          row.sourceDigest,
          authority.bytes,
          authority.digest,
        ],
      );
      return { ...command, dispatchId, dispatch: true };
    },
  );
}
