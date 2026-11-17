import type { Pool, PoolClient } from 'pg';
import { z } from 'zod';
import { workloadSigningHandoverAdmissionOperation as operation } from '../../../../packages/security-kernel/src/workload-signing-handover-operations.js';
import {
  handoverAdmissionCandidateRequestSchema,
  handoverAdmissionCandidateSchema,
  buildHandoverAdmissionCandidate,
  type HandoverAdmissionCandidateRequest,
  type HandoverAdmissionCandidate,
} from '../domain/workload-signing-handover-admission-candidate.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import { localOperationId } from '../domain/local-operation-id.js';
import { runScopedTransaction } from './scoped-transaction.js';
import { fenceBoundAuthorities } from './authority-fence.js';
import { stageMutationCandidateInTransaction } from './mutation-candidate-store.js';
import { captureHandoverAdmissionMaterial } from './workload-signing-handover-admission-reader.js';
import {
  canonical,
  idempotency,
  fail,
  type WorkloadSigningHandoverScope,
} from './workload-signing-handover-custody.js';

interface CandidateRow {
  candidateId: string;
  handoverId: string;
  document: unknown;
  digest: Buffer;
  state: 'PROPOSED' | 'APPROVAL_REQUESTED' | 'APPROVED' | 'CONSUMED' | 'CANCELLED';
  expired: boolean;
}
async function originalCandidate(
  client: PoolClient,
  scope: WorkloadSigningHandoverScope,
  key: string,
) {
  const result = await client.query<CandidateRow>(
    `select mutation_candidate_id::text as "candidateId",resource_id::text as "handoverId",
       candidate_document as document,candidate_digest as digest,state,
       expires_at<=clock_timestamp() as expired
     from control.mutation_candidate
     where participant_id=$1 and privacy_domain_id=$2 and maker_principal_id=$3
       and action_intent_id=$4 and catalog_operation_id=$5 and idempotency_key=$6
     order by attempt`,
    [
      scope.participantId,
      scope.privacyDomainId,
      scope.authority.principalId,
      operation.actionIntentId,
      operation.catalogOperationId,
      key,
    ],
  );
  if (result.rowCount !== 0 && result.rowCount !== 1) fail('CORRUPT');
  return result.rows[0];
}
function authenticateCandidate(
  row: CandidateRow,
  scope: WorkloadSigningHandoverScope,
  handoverId: string,
  request: HandoverAdmissionCandidateRequest,
): HandoverAdmissionCandidate {
  const document = handoverAdmissionCandidateSchema.parse(row.document);
  if (
    row.handoverId !== handoverId ||
    document.handoverId !== handoverId ||
    document.participantId !== scope.participantId ||
    document.privacyDomainId !== scope.privacyDomainId ||
    document.environmentId !== scope.environmentId ||
    document.makerPrincipalId !== scope.authority.principalId ||
    canonicalAuthorizationDigest(document) !== 'sha256:' + row.digest.toString('hex')
  )
    fail('CORRUPT');
  if (!canonical(document.request).equals(canonical(request))) fail('CONFLICT');
  return document;
}
function view(row: CandidateRow, document: HandoverAdmissionCandidate) {
  return {
    handoverId: document.handoverId,
    candidateId: row.candidateId,
    candidateDigest: 'sha256:' + row.digest.toString('hex'),
    generationId: document.generation.generationId,
    state:
      row.state === 'CONSUMED' || row.state === 'CANCELLED'
        ? row.state
        : row.expired
          ? ('EXPIRED' as const)
          : row.state,
    expiresAtNs: document.expiresAtNs,
    keyCount: document.predecessorTrusts.length,
    receiptSelectionCount: document.source.receiptSelections.length,
    envelopeSelectionCount: document.source.envelopeSelections.length,
    document,
  };
}

/** The ordinary immutable candidate/approval owner is the durable store. No
 * parallel proposal state, provider dispatch, trust or selection is created.
 * Exact replay reads the original body, including after its proof expires. */
export async function stageWorkloadSigningHandoverAdmissionCandidate(
  pool: Pool,
  scope: WorkloadSigningHandoverScope,
  handoverIdInput: string,
  requestInput: HandoverAdmissionCandidateRequest,
  idempotencyKey: string,
) {
  const handoverId = z.uuidv7().parse(handoverIdInput),
    request = handoverAdmissionCandidateRequestSchema.parse(requestInput);
  const key = idempotency.parse(idempotencyKey);
  if (
    scope.authority.actionIntentId !== operation.actionIntentId ||
    scope.authority.catalogOperationId !== operation.catalogOperationId ||
    scope.authority.resourceId !== handoverId ||
    scope.authority.privacyDomainId !== scope.privacyDomainId
  )
    fail('DENIED');
  return runScopedTransaction(
    pool,
    { ...scope, actionIntentId: operation.actionIntentId, isolation: 'SERIALIZABLE' },
    localOperationId,
    async (client) => {
      await fenceBoundAuthorities(client, scope.participantId, [scope.authority]);
      const original = await originalCandidate(client, scope, key);
      if (original)
        return view(original, authenticateCandidate(original, scope, handoverId, request));
      const material = await captureHandoverAdmissionMaterial(
        client,
        scope,
        handoverId,
        request.generationId,
      );
      const document = buildHandoverAdmissionCandidate({
        source: material.captured.document,
        workloadId: material.captured.workloadId,
        trusts: material.captured.trusts,
        generation: material.generation,
        proofs: material.proofs,
        request,
        preparedAtNs: material.captured.recordedAtNs.toString(),
      });
      await stageMutationCandidateInTransaction(client, {
        authorization: { ...scope.authority, participantId: scope.participantId },
        participantId: scope.participantId,
        privacyDomainId: scope.privacyDomainId,
        actionIntentId: operation.actionIntentId,
        actionIntentDigest: request.actionIntentDigest,
        catalogOperationId: operation.catalogOperationId,
        resourceType: operation.resourceType,
        operationClass: operation.operationClass,
        resourceId: handoverId,
        serverGeneratedResourceId: false,
        expectedRevision: '1',
        idempotencyKey: key,
        candidateDigest: canonicalAuthorizationDigest(document),
        candidate: document,
      });
      const saved = await originalCandidate(client, scope, key);
      if (!saved) fail('CORRUPT');
      return view(saved, authenticateCandidate(saved, scope, handoverId, request));
    },
  );
}
