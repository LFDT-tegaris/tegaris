import type { PoolClient } from 'pg';
import { readWorkloadPolicyPrediction } from '../../../identity-service/src/domain/workload-policy-prediction.js';

import { pcCbor1 } from '../domain/digest.js';
import { ContractError } from '../domain/errors.js';
import type { EvaluationResult } from '../domain/policy-evaluator.js';
import { PolicyFactReader, type PolicyFactSnapshot } from '../domain/policy-facts.js';
import {
  simulateContractSemantics,
  validatePolicySemantics,
  type PolicySimulationRequest,
} from '../domain/policy-semantics.js';
import type { AuthorizedPolicyActor } from '../policy-http.js';
import { assertPolicyModuleBindings, loadPolicyContractInputs } from './policy-inputs.js';
import { loadPolicyDeploymentInputs } from './deployment-policy-inputs.js';
import { loadPolicyIndexerInputs } from './indexer-policy-inputs.js';
import { loadPolicyVisibilityInputs } from './visibility-policy-inputs.js';
import { resolveContractSimulationAuthority } from './policy-simulation-authority.js';

function stableSnapshot(value: PolicyFactSnapshot | null) {
  if (value === null) return null;
  return Object.fromEntries(Object.entries(value).filter(([key]) => key !== 'snapshotAtMs'));
}

/** Resolve policy meaning and authority at their owners. The request contains
 * only the selected reference and transaction or method inputs. */
export async function materializePolicySimulation(
  client: PoolClient,
  version: {
    readonly semantic_cbor: Buffer;
    readonly semantic_digest: Buffer;
    readonly dependency_closure_digest: Buffer;
  },
  actor: AuthorizedPolicyActor,
  privacyDomainId: string,
  request: PolicySimulationRequest,
  facts: Pick<PolicyFactReader, 'read'>,
  requireActive = false,
): Promise<{ readonly evaluation: EvaluationResult; readonly factDigest: Buffer }> {
  const decoded = validatePolicySemantics(Array.from(version.semantic_cbor), 'DECODE_SEMANTICS');
  const document = decoded.document;
  if (
    !decoded.digest.equals(version.semantic_digest) ||
    document.participantId !== actor.participantId ||
    document.privacyDomainId !== privacyDomainId
  )
    throw new ContractError('PC-POLICY-2004');
  await assertPolicyModuleBindings(
    client,
    document,
    version.dependency_closure_digest,
    requireActive,
  );
  const admitted = await loadPolicyContractInputs(client, document);
  const deployments = await loadPolicyDeploymentInputs(client, document);
  const indexerInputs = await loadPolicyIndexerInputs(client, document);
  const visibilityInputs = await loadPolicyVisibilityInputs(client, document);
  const evaluatedAtMs = Number(
    (
      await client.query<{ now: string }>(
        `select floor(extract(epoch from clock_timestamp())*1000)::text as now`,
      )
    ).rows[0]!.now,
  );
  const selectedSource =
    'indexerProfileId' in request
      ? document.indexerPolicies?.find(
          (policy) =>
            policy.indexerProfileId === request.indexerProfileId &&
            policy.projectionPlanId === request.projectionPlanId,
        )
      : undefined;
  if ('indexerProfileId' in request && selectedSource === undefined)
    throw new ContractError('PC-POLICY-2003', 'simulation source reference unavailable');
  const selectedVisibility =
    'visibilityPolicyId' in request
      ? document.visibilityPolicies?.find(
          (policy) => policy.policyId === request.visibilityPolicyId,
        )
      : undefined;
  if ('visibilityPolicyId' in request && selectedVisibility === undefined)
    throw new ContractError('PC-POLICY-2003', 'simulation visibility reference unavailable');
  const selectedContractAuthority =
    'contractMethodPolicyId' in request && request.workloadId && request.assignmentId
      ? await resolveContractSimulationAuthority(
          client,
          actor.participantId,
          privacyDomainId,
          request.workloadId,
          request.assignmentId,
          evaluatedAtMs,
        )
      : undefined;
  const predictedWorkload =
    selectedSource?.workloadId ??
    (selectedVisibility?.subject.kind === 'WORKLOAD'
      ? selectedVisibility.subject.workloadId
      : selectedContractAuthority?.workloadId);
  const prediction =
    predictedWorkload === undefined
      ? undefined
      : await readWorkloadPolicyPrediction(
          client,
          actor.participantId,
          privacyDomainId,
          predictedWorkload,
          evaluatedAtMs,
        );
  let snapshots: readonly (PolicyFactSnapshot | null)[];
  try {
    snapshots = await facts.read(document, predictedWorkload ?? actor.principalId);
  } catch {
    throw new ContractError('PC-POLICY-2003', 'required fact owner unavailable');
  }
  const semantic = simulateContractSemantics(
    document,
    admitted,
    {
      participantId: actor.participantId,
      privacyDomainId,
      principalId: selectedContractAuthority?.principalId ?? actor.principalId,
      workloadId: selectedContractAuthority?.workloadId,
      assignmentId: selectedContractAuthority?.assignmentId ?? actor.assignmentId,
      roles: selectedContractAuthority ? [selectedContractAuthority.roleId] : (actor.roleIds ?? []),
      authorityDigest:
        selectedContractAuthority?.authorityDigest ?? pcCbor1(actor).digest.toString('hex'),
    },
    request,
    snapshots,
    deployments,
    evaluatedAtMs,
    indexerInputs,
    prediction?.input,
    visibilityInputs,
  );
  const factIdentity = pcCbor1(snapshots.map(stableSnapshot));
  // Read once more after evaluation: a concurrent reorg, readiness loss or
  // freshness expiry must invalidate this simulation before persistence.
  try {
    const current = await facts.read(document, predictedWorkload ?? actor.principalId);
    if (!pcCbor1(current.map(stableSnapshot)).digest.equals(factIdentity.digest))
      throw new Error('fact owner changed');
  } catch {
    throw new ContractError('PC-POLICY-2003', 'required fact state changed');
  }
  if (
    deployments.length > 0 &&
    !pcCbor1(await loadPolicyDeploymentInputs(client, document)).digest.equals(
      pcCbor1(deployments).digest,
    )
  )
    throw new ContractError('PC-POLICY-2003', 'deployment publication changed');
  if (
    visibilityInputs.length > 0 &&
    !pcCbor1(await loadPolicyVisibilityInputs(client, document)).digest.equals(
      pcCbor1(visibilityInputs).digest,
    )
  )
    throw new ContractError('PC-POLICY-2003', 'visibility publication changed');
  if (prediction !== undefined && predictedWorkload !== undefined) {
    const now = Number(
      (
        await client.query<{ now: string }>(
          `select floor(extract(epoch from clock_timestamp())*1000)::text as now`,
        )
      ).rows[0]!.now,
    );
    const current = await readWorkloadPolicyPrediction(
      client,
      actor.participantId,
      privacyDomainId,
      predictedWorkload,
      now,
    );
    if (
      now < evaluatedAtMs ||
      current.input.sourceDigest !== prediction.input.sourceDigest ||
      current.input.credentialValidUntilNs !== prediction.input.credentialValidUntilNs ||
      (prediction.nextTransitionNs !== undefined &&
        BigInt(now) * 1_000_000n >= prediction.nextTransitionNs)
    )
      throw new ContractError('PC-POLICY-2003', 'simulation workload authority changed');
  }
  const { factGenerationDigest, ...evaluation } = semantic;
  return { factDigest: Buffer.from(factGenerationDigest, 'hex'), evaluation };
}
