import type { PoolClient } from 'pg';
import { workloadSigningHandoverAdmissionOperation as operation } from '../../../../packages/security-kernel/src/workload-signing-handover-operations.js';
import {
  buildHandoverAdmissionCandidate,
  handoverAdmissionCandidateSchema,
  type HandoverAdmissionCandidate,
} from '../domain/workload-signing-handover-admission-candidate.js';
import { fenceBoundAuthorities, type AuthorityFence } from './authority-fence.js';
import { captureWorkloadSigningHandoverAdmissionSource } from './workload-signing-handover-source.js';
import {
  loadWorkloadSigningHandoverGeneration,
  assertHandoverGenerationCanDispatch,
} from './workload-signing-handover-generation-reader.js';
import { loadWorkloadSigningHandoverAttempt } from './workload-signing-handover-store.js';
import { readWorkloadSigningHandoverObservationsInTransaction } from './workload-signing-handover-observations.js';
import {
  canonical,
  retained,
  fail,
  type WorkloadSigningHandoverScope,
} from './workload-signing-handover-custody.js';

export async function captureHandoverAdmissionMaterial(
  client: PoolClient,
  scope: WorkloadSigningHandoverScope,
  handoverId: string,
  generationId: string,
) {
  if (
    scope.authority.actionIntentId !== operation.actionIntentId ||
    scope.authority.catalogOperationId !== operation.catalogOperationId ||
    scope.authority.resourceId !== handoverId ||
    scope.authority.privacyDomainId !== scope.privacyDomainId
  )
    fail('DENIED');
  await fenceBoundAuthorities(client, scope.participantId, [scope.authority]);
  const original = await retained(client, scope, handoverId);
  const captured = await captureWorkloadSigningHandoverAdmissionSource(
    client,
    { ...scope, handoverId },
    original.request,
  );
  if (!canonical(captured.document).equals(original.sourceCanonical)) fail('CONFLICT');
  const saved = await loadWorkloadSigningHandoverGeneration(client, scope, generationId);
  if (saved.handoverId !== handoverId || saved.makerPrincipalId !== scope.authority.principalId)
    fail('DENIED');
  await assertHandoverGenerationCanDispatch(client, scope, saved.document);
  const reused = await client.query(
    `select 1 from control.business_signing_key where participant_id=$1 and privacy_domain_id=$2 and signer_id=any($3::text[]) limit 1`,
    [
      scope.participantId,
      scope.privacyDomainId,
      saved.document.keys.map((key) => key.observation.descriptor!.fingerprint),
    ],
  );
  if (reused.rowCount !== 0) fail('CONFLICT');
  const commands = await client.query<{ attemptId: string; dispatchId: string }>(
    `select a.attempt_id::text as "attemptId",d.dispatch_id::text as "dispatchId"
     from control.workload_signing_handover_attempt a join control.workload_signing_handover_dispatch d
       on d.participant_id=a.participant_id and d.privacy_domain_id=a.privacy_domain_id and d.attempt_id=a.attempt_id
     where a.participant_id=$1 and a.privacy_domain_id=$2 and a.handover_id=$3 and a.generation_id=$4 and a.stage='POSSESSION'
     order by a.predecessor_fingerprint`,
    [scope.participantId, scope.privacyDomainId, handoverId, generationId],
  );
  if (commands.rowCount !== saved.document.keys.length) fail('CONFLICT');
  const proofs = [];
  for (const command of commands.rows) {
    const loaded = await loadWorkloadSigningHandoverAttempt(client, scope, command.attemptId);
    if (!('stage' in loaded.attempt) || loaded.attempt.generationId !== generationId)
      fail('CORRUPT');
    const observed = await readWorkloadSigningHandoverObservationsInTransaction(
      client,
      scope,
      command.attemptId,
      command.dispatchId,
    );
    if (observed.state !== 'OBSERVED' || observed.firstObservation?.outcome !== 'SUCCEEDED')
      fail('CONFLICT');
    proofs.push({ attempt: loaded.attempt, observation: observed.firstObservation });
  }
  return { captured, generation: saved.document, proofs };
}

/** Discovery only, before the shared ranked authority fence. No business row
 * lock, external I/O or new authority follows from these public identifiers. */
export function handoverAdmissionAuthorityDependencies(
  input: HandoverAdmissionCandidate,
): AuthorityFence {
  const candidate = handoverAdmissionCandidateSchema.parse(input);
  return {
    principal: [{ id: candidate.source.issuer.workloadPrincipalId }],
    credential: [
      { id: candidate.source.provenance.predecessorCredentialId },
      { id: candidate.source.issuer.workloadCredentialId },
    ],
  };
}

/** Called after all actual maker/checker/workload fences and before decision
 * writes. Rebuild from current native owners; an earlier valid body is not a
 * cached readiness assertion or a substitute for current possession. */
export async function assertCurrentHandoverAdmissionCandidate(
  client: PoolClient,
  scope: WorkloadSigningHandoverScope,
  input: HandoverAdmissionCandidate,
) {
  const candidate = handoverAdmissionCandidateSchema.parse(input);
  if (
    candidate.makerPrincipalId !== scope.authority.principalId ||
    candidate.participantId !== scope.participantId ||
    candidate.privacyDomainId !== scope.privacyDomainId ||
    candidate.environmentId !== scope.environmentId
  )
    fail('DENIED');
  const intent = await client.query(
    `select 1 from control.action_intent where action_intent_id=$1 and semantic_digest=decode($2,'hex')
      and resource_type=$3 and operation_class='ACTIVATE' and maker_checker_required=true
      and step_up_required=true and idempotency_required=true`,
    [
      operation.actionIntentId,
      candidate.request.actionIntentDigest.slice(7),
      operation.resourceType,
    ],
  );
  if (intent.rowCount !== 1) fail('CONFLICT');
  const material = await captureHandoverAdmissionMaterial(
    client,
    scope,
    candidate.handoverId,
    candidate.generation.generationId,
  );
  if (BigInt(candidate.preparedAtNs) > material.captured.recordedAtNs) fail('CORRUPT');
  const fresh = buildHandoverAdmissionCandidate({
    source: material.captured.document,
    workloadId: material.captured.workloadId,
    trusts: material.captured.trusts,
    generation: material.generation,
    proofs: material.proofs,
    request: candidate.request,
    preparedAtNs: candidate.preparedAtNs,
  });
  if (!canonical(fresh).equals(canonical(candidate))) fail('CONFLICT');
  return candidate;
}
