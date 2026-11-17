import { createHash } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import { z } from 'zod';
import { canonicalDefinitionJson } from '../../../../packages/security-kernel/src/business-transition/definition.js';
import { signingRotationActions } from '../../../../packages/security-kernel/src/signing-operations.js';
import {
  handoverProviderResultBytes,
  handoverProviderResultDigest,
  summarizeHandoverProviderResults,
  validateHandoverProviderResult,
  type HandoverProviderResult,
} from '../domain/workload-signing-handover-result.js';
import { localOperationId } from '../domain/local-operation-id.js';
import { runScopedTransaction } from './scoped-transaction.js';
import {
  loadWorkloadSigningHandoverAttempt,
  WorkloadSigningHandoverStoreError,
  type WorkloadSigningHandoverAttemptScope,
} from './workload-signing-handover-store.js';

const tagged = (bytes: Buffer) => 'sha256:' + bytes.toString('hex');
const canonical = (value: unknown) => Buffer.from(canonicalDefinitionJson(value));
const entryDigest = (bytes: Buffer) =>
  createHash('sha256')
    .update('pc.identity.workload-signing-handover.observation-entry.v1\0')
    .update(bytes)
    .digest();
type Command = Awaited<ReturnType<typeof loadWorkloadSigningHandoverAttempt>>;
interface ObservationRow {
  observationId: string;
  operationId: string;
  sequence: number;
  result: HandoverProviderResult;
  resultCanonical: Buffer;
  resultDigest: Buffer;
  previousDigest: Buffer | null;
  entryCanonical: Buffer;
  entryDigest: Buffer;
  recordedAtNs: string;
}
function entry(
  scope: WorkloadSigningHandoverAttemptScope,
  command: Command,
  dispatchId: string,
  row: Pick<
    ObservationRow,
    | 'observationId'
    | 'operationId'
    | 'sequence'
    | 'previousDigest'
    | 'resultDigest'
    | 'recordedAtNs'
  >,
) {
  return canonical({
    schemaVersion: 1,
    participantId: scope.participantId,
    privacyDomainId: scope.privacyDomainId,
    handoverId: command.handoverId,
    attemptId: command.attempt.request.attemptId,
    dispatchId,
    observationId: row.observationId,
    operationId: row.operationId,
    sequence: row.sequence,
    previousDigest: row.previousDigest === null ? null : tagged(row.previousDigest),
    resultDigest: tagged(row.resultDigest),
    recordedAtNs: row.recordedAtNs,
  });
}
async function readDispatch(
  client: PoolClient,
  scope: WorkloadSigningHandoverAttemptScope,
  command: Command,
  dispatchId: string,
) {
  const selected = await client.query<{
    attemptId: string;
    handoverId: string;
    attemptDigest: Buffer;
    sourceDigest: Buffer;
  }>(
    `select attempt_id::text as "attemptId",handover_id::text as "handoverId",attempt_digest as "attemptDigest",source_digest as "sourceDigest"
     from control.workload_signing_handover_dispatch where participant_id=$1 and privacy_domain_id=$2 and dispatch_id=$3`,
    [scope.participantId, scope.privacyDomainId, z.uuidv7().parse(dispatchId)],
  );
  if (selected.rowCount !== 1) throw new WorkloadSigningHandoverStoreError('NOT_FOUND');
  const row = selected.rows[0]!;
  if (
    row.attemptId !== command.attempt.request.attemptId ||
    row.handoverId !== command.handoverId ||
    !row.attemptDigest.equals(command.attemptDigest) ||
    tagged(row.sourceDigest) !== command.binding.sourceDigest
  )
    throw new WorkloadSigningHandoverStoreError('CORRUPT');
}
async function history(
  client: PoolClient,
  scope: WorkloadSigningHandoverAttemptScope,
  command: Command,
  dispatchId: string,
) {
  const selected = await client.query<ObservationRow>(
    `select observation_id::text as "observationId",operation_id::text as "operationId",sequence,result,
     result_canonical as "resultCanonical",result_digest as "resultDigest",previous_digest as "previousDigest",
     entry_canonical as "entryCanonical",entry_digest as "entryDigest",recorded_at_ns::text as "recordedAtNs"
     from control.workload_signing_handover_observation where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3 order by sequence`,
    [scope.participantId, scope.privacyDomainId, command.attempt.request.attemptId],
  );
  let previous: ObservationRow | undefined;
  for (const row of selected.rows) {
    const result = validateHandoverProviderResult(
      command.binding,
      command.attempt,
      row.result,
      command.generation,
    );
    if (
      row.sequence !== (previous?.sequence ?? 0) + 1 ||
      (previous
        ? !row.previousDigest?.equals(previous.entryDigest)
        : row.previousDigest !== null) ||
      (previous && BigInt(row.recordedAtNs) < BigInt(previous.recordedAtNs)) ||
      !handoverProviderResultBytes(result).equals(row.resultCanonical) ||
      !handoverProviderResultDigest(result).equals(row.resultDigest) ||
      !entry(scope, command, dispatchId, row).equals(row.entryCanonical) ||
      !entryDigest(row.entryCanonical).equals(row.entryDigest)
    )
      throw new WorkloadSigningHandoverStoreError('CORRUPT');
    previous = row;
  }
  return selected.rows;
}
function view(rows: readonly ObservationRow[]) {
  return {
    ...summarizeHandoverProviderResults(rows.map((row) => row.result)),
    observationCount: rows.length,
    lastEntryDigest: rows.length ? tagged(rows[rows.length - 1]!.entryDigest) : null,
  };
}
export async function readWorkloadSigningHandoverObservationsInTransaction(
  client: PoolClient,
  scope: WorkloadSigningHandoverAttemptScope,
  attemptId: string,
  dispatchId: string,
) {
  const command = await loadWorkloadSigningHandoverAttempt(client, scope, attemptId);
  await readDispatch(client, scope, command, dispatchId);
  return view(await history(client, scope, command, dispatchId));
}

/** Internal collector scope only; a public reader must separately authorize and
 * filter its response. No human lease is reused to authorize a new effect. */
export async function readWorkloadSigningHandoverObservations(
  pool: Pool,
  scope: WorkloadSigningHandoverAttemptScope,
  attemptId: string,
  dispatchId: string,
) {
  const exactScope = {
    participantId: z.uuidv7().parse(scope.participantId),
    privacyDomainId: z.uuidv7().parse(scope.privacyDomainId),
  };
  return runScopedTransaction(
    pool,
    { ...exactScope, actionIntentId: signingRotationActions.create },
    localOperationId,
    async (client) => {
      return readWorkloadSigningHandoverObservationsInTransaction(
        client,
        exactScope,
        attemptId,
        dispatchId,
      );
    },
  );
}

/** A late valid response can be retained after authority expiry. The append is
 * evidence custody only: it cannot admit trust, change selectors or redispatch. */
export async function recordWorkloadSigningHandoverObservation(
  pool: Pool,
  scope: WorkloadSigningHandoverAttemptScope,
  attemptId: string,
  dispatchId: string,
  input: HandoverProviderResult,
) {
  const exactScope = {
    participantId: z.uuidv7().parse(scope.participantId),
    privacyDomainId: z.uuidv7().parse(scope.privacyDomainId),
  };
  return runScopedTransaction(
    pool,
    { ...exactScope, actionIntentId: signingRotationActions.create },
    localOperationId,
    async (client, operationId) => {
      const command = await loadWorkloadSigningHandoverAttempt(client, exactScope, attemptId);
      await readDispatch(client, exactScope, command, dispatchId);
      const result = validateHandoverProviderResult(
        command.binding,
        command.attempt,
        input,
        command.generation,
      );
      await client.query(
        `select pg_advisory_xact_lock(hashtextextended('pc.identity.workload-signing-handover.observation:'||$1,0))`,
        [attemptId],
      );
      const rows = await history(client, exactScope, command, dispatchId);
      const previous = rows[rows.length - 1];
      const resultCanonical = handoverProviderResultBytes(result);
      if (previous?.resultCanonical.equals(resultCanonical)) return view(rows);
      const clock = await client.query<{ now: string }>(
        'select (floor(extract(epoch from clock_timestamp())*1000000)*1000)::numeric(20,0)::text as now',
      );
      const row = {
        observationId: localOperationId(),
        operationId,
        sequence: (previous?.sequence ?? 0) + 1,
        previousDigest: previous?.entryDigest ?? null,
        resultDigest: handoverProviderResultDigest(result),
        recordedAtNs: clock.rows[0]!.now,
      };
      const entryCanonical = entry(exactScope, command, dispatchId, row);
      await client.query(
        `insert into control.workload_signing_handover_observation(participant_id,privacy_domain_id,handover_id,attempt_id,dispatch_id,
       observation_id,operation_id,sequence,result,result_canonical,result_digest,previous_digest,entry_canonical,entry_digest,recorded_at_ns)
       values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
        [
          exactScope.participantId,
          exactScope.privacyDomainId,
          command.handoverId,
          attemptId,
          dispatchId,
          row.observationId,
          operationId,
          row.sequence,
          result,
          resultCanonical,
          row.resultDigest,
          row.previousDigest,
          entryCanonical,
          entryDigest(entryCanonical),
          row.recordedAtNs,
        ],
      );
      return view(await history(client, exactScope, command, dispatchId));
    },
  );
}
