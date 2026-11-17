import { createHash } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import { AtomicConfigurationMutation } from '../../../control-api/src/configuration/persistence/atomic-mutation.js';
import {
  ConfigurationRepositoryError,
  type MutationContext,
} from '../../../control-api/src/configuration/persistence/types.js';
import type { ConfigurationBusinessEvidence } from '../../../control-api/src/configuration/persistence/business-receipt-writer.js';
import type { IdentityRuntimeVerifier } from '../../../identity-service/src/domain/identity-runtime-crypto.js';
import {
  policyActivationRenewalSourceSchema,
  type PolicyActivationRenewalSource,
  type RenewPolicyActivation,
} from '../policy-activation-renewal-contract.js';
import { ContractError } from '../domain/errors.js';
import {
  occurrenceRow,
  releaseCandidate,
  exactTargets,
  cohortDigest,
  stepUpProof,
  preparePolicyActivation,
  dispatchTarget,
  type ActivationScope,
  type OccurrenceRow,
  type ReleaseCandidate,
} from './public-activation-store.js';
import { inScope, assertActionIntent, type PublicApprovalScope } from './public-approval-store.js';
import {
  assertPolicyRenewalSource,
  policyRenewalTargetRevisionMatches,
} from './policy-activation-renewal-source.js';
import { canonicalJson } from '../domain/digest.js';

const digest = (value: unknown) => createHash('sha256').update(canonicalJson(value)).digest();
const digestString = (value: Buffer) => `sha256:${value.toString('hex')}`;
const urn = (id: string) => `urn:openpc:resource:${id}`;
function rejectRenewalSource(
  stage: string,
  occurrenceId: string,
  code: 'PC-POLICY-2003' | 'PC-POLICY-2004',
): never {
  process.stderr.write(
    JSON.stringify({
      boundary: 'policy_activation_renewal',
      stage,
      occurrenceId,
      errorCode: code,
      disposition: 'NO_EFFECT',
    }) + '\n',
  );
  throw new ContractError(code);
}

/** Disposable QA's separately installed bootstrap administration is not typed
 * Root administration. Only explicitly pinned initial trust is compatible. */
export function initialQaPolicyRenewalEnvelope(
  env: Readonly<Record<string, string | undefined>>,
  authorityEnvelopeId: string,
): boolean {
  if (env.OPENPC_LOCAL_RUNTIME !== '1' || env.OPENPC_LOCAL_RUNTIME_QA_FIXTURE !== '1') return false;
  const ids = env.OPENPC_LOCAL_QA_INITIAL_POLICY_RENEWAL_ENVELOPE_IDS?.split(',') ?? [];
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
  return ids.length > 0 && ids.every((id) => uuid.test(id)) && ids.includes(authorityEnvelopeId);
}

/** Historical compilation/release provenance is retained; this snapshot binds
 * fresh governed custody to actual current authority and target predecessors. */
async function policyRenewalSource(
  client: PoolClient,
  scope: ActivationScope,
  id: string,
  authorityEnvelopeId: string,
): Promise<{
  source: PolicyActivationRenewalSource;
  occurrence: OccurrenceRow;
  release: ReleaseCandidate;
}> {
  const occurrence = await occurrenceRow(client, scope, id, true);
  if (occurrence.state !== 'REQUESTED') throw new ContractError('PC-POLICY-2003');
  const release = await releaseCandidate(
    client,
    scope,
    occurrence.releaseBundleId,
    occurrence.targetGenerationDigest,
  );
  const targets = await exactTargets(client, scope);
  if (
    targets.length !== Number(occurrence.totalTargetCount) ||
    !cohortDigest(targets).equals(occurrence.exactCohortDigest)
  )
    throw new ContractError('PC-POLICY-2003');
  const retained = await client.query<{ initialPrepared: boolean }>(
    `select generation.state='PREPARED' as "initialPrepared" from control.policy_generation generation
     where generation.participant_id=$1 and generation.privacy_domain_id=$2 and generation.policy_generation_id=$3
       and generation.policy_version_id=$4 and generation.generation_digest=$5
       and generation.artifact_digest=$6 and generation.compiler_manifest_digest=$7
       and generation.dependency_closure_digest=$8
       and ((generation.state='ACTIVE' and generation.active) or
         (generation.state='PREPARED' and not generation.active
           and not exists (select 1 from control.policy_activation activation
             where activation.participant_id=$1 and activation.privacy_domain_id=$2
               and activation.policy_generation_id=generation.policy_generation_id)
           and not exists (select 1 from control.runtime_configuration_generation runtime
             where runtime.participant_id=$1 and runtime.privacy_domain_id=$2
               and runtime.policy_generation_digest='sha256:'||encode(generation.generation_digest,'hex'))
           and not exists (select 1 from control.policy_activation_occurrence_target initial_cohort
             where initial_cohort.activation_occurrence_id=$9
               and (initial_cohort.phase<>'FORWARD' or initial_cohort.state<>'REQUESTED'
                 or initial_cohort.expected_predecessor_digest is not null
                 or initial_cohort.configuration_work_id is not null
                 or initial_cohort.runtime_configuration_generation_id is not null
                 or initial_cohort.command_operation_id is not null
                 or initial_cohort.observed_generation_digest is not null
                 or initial_cohort.activation_receipt_digest is not null))))
       and not exists (select 1 from control.policy_activation_occurrence other
         where other.policy_generation_id=generation.policy_generation_id and other.activation_occurrence_id<>$9
           and other.state in ('REQUESTED','STAGING','PARTIAL','ROLLING_BACK'))
       and not exists (select 1 from control.policy_activation_occurrence_target cohort
         join control.runtime_target target on target.runtime_target_id=cohort.runtime_target_id
           and target.participant_id=cohort.participant_id and target.privacy_domain_id=cohort.privacy_domain_id
         where cohort.activation_occurrence_id=$9 and cohort.phase='FORWARD'
           and (cohort.configuration_work_id is not null or cohort.state not in ('REQUESTED','ACTIVE_MATCHED')
             or cohort.expected_predecessor_digest is distinct from target.active_generation_digest))
       and not exists (select 1 from control.runtime_activation_observation observation
         join control.runtime_configuration_generation runtime on runtime.runtime_configuration_generation_id=observation.runtime_configuration_generation_id
         join control.runtime_target target on target.runtime_target_id=observation.runtime_target_id
           and target.participant_id=observation.participant_id and target.privacy_domain_id=observation.privacy_domain_id
           and target.active_generation_digest=observation.capsule_digest
         where target.participant_id=$1 and target.privacy_domain_id=$2 and runtime.cigl_profile_selection is not null)
     for share of generation`,
    [
      scope.participantId,
      scope.privacyDomainId,
      occurrence.policyGenerationId,
      release.policyVersionId,
      release.manifestDigest,
      release.artifactPayloadDigest,
      release.schemaDigest,
      release.dependencyClosureDigest,
      id,
    ],
  );
  if (retained.rowCount !== 1 || typeof retained.rows[0]?.initialPrepared !== 'boolean')
    rejectRenewalSource('retained_generation_and_no_prior_effect', id, 'PC-POLICY-2003');
  const originalRevisions = await client.query<{
    targetId: string;
    expectedRevision: string;
    requiresAuthenticatedDiscovery: boolean;
  }>(
    `select cohort.runtime_target_id::text as "targetId",
            cohort.expected_target_revision::text as "expectedRevision",
            target.requires_authenticated_discovery as "requiresAuthenticatedDiscovery"
       from control.policy_activation_occurrence_target cohort
       join control.runtime_target target on target.runtime_target_id=cohort.runtime_target_id
        and target.participant_id=cohort.participant_id and target.privacy_domain_id=cohort.privacy_domain_id
      where cohort.participant_id=$1 and cohort.privacy_domain_id=$2 and cohort.activation_occurrence_id=$3
        and cohort.phase='FORWARD' order by cohort.runtime_target_id for share of cohort`,
    [scope.participantId, scope.privacyDomainId, id],
  );
  const originalByTarget = new Map(
    originalRevisions.rows.map((target) => [target.targetId, target]),
  );
  if (
    originalRevisions.rowCount !== targets.length ||
    originalByTarget.size !== targets.length ||
    targets.some((target) => {
      const original = originalByTarget.get(target.targetId);
      return (
        original === undefined ||
        !policyRenewalTargetRevisionMatches(
          retained.rows[0]!.initialPrepared,
          original.expectedRevision,
          { ...target, requiresAuthenticatedDiscovery: original.requiresAuthenticatedDiscovery },
        )
      );
    })
  )
    rejectRenewalSource('current_target_revisions', id, 'PC-POLICY-2003');
  const root = await client.query<{
    platformContextId: string;
    platformAuthorityEpoch: string;
    platformRevision: string;
  }>(
    `select root.platform_context_id::text as "platformContextId",root.authority_epoch::text as "platformAuthorityEpoch",
            root.row_version::text as "platformRevision"
       from control.authority_envelope envelope
       cross join lateral openpc.lock_platform_scope_context(envelope.platform_context_id) root
       where envelope.participant_id=$1 and envelope.authority_envelope_id=$2 and envelope.state='ACTIVE'
         and root.platform_context_id=envelope.platform_context_id and root.owner_participant_id=envelope.participant_id
         and (envelope.representation='TYPED_V1' or
           ($3::boolean and envelope.representation='LEGACY' and root.authority_epoch=1
             and envelope.semantic_digest=sha256(envelope.semantic_cbor)
             and openpc.business_cbor(envelope.semantic_cbor)->>0='SYNTHETIC_LOCAL_QA_TRUST'
             and not exists (select 1 from control.platform_envelope_scope_successor successor
               where successor.platform_context_id=root.platform_context_id)
             and exists (select 1 from control.platform_envelope_scope installation
               where installation.platform_context_id=root.platform_context_id
                 and installation.owner_participant_id=envelope.participant_id
                 and installation.installation_privacy_domain_id=$4::uuid
                 and installation.platform_authority_epoch=root.authority_epoch
                 and installation.admission_version=1
                 and installation.admission_digest=sha256(installation.admission_preimage))))
         and root.state='ACTIVE'
         and envelope.platform_authority_epoch=root.authority_epoch
         and not exists (select 1 from control.platform_scope_replacement pending
           where pending.platform_context_id=root.platform_context_id and pending.state='WITHDRAWING')
       for share of envelope`,
    [
      scope.participantId,
      authorityEnvelopeId,
      retained.rows[0]!.initialPrepared &&
        initialQaPolicyRenewalEnvelope(process.env, authorityEnvelopeId),
      scope.privacyDomainId,
    ],
  );
  if (root.rowCount !== 1)
    rejectRenewalSource('current_root_and_initial_trust', id, 'PC-POLICY-2004');
  const providers = await client.query<{
    providerProfileId: string;
    providerRevision: string;
    providerFingerprint: string;
    providerObservationId: string;
    providerObservationDigest: string;
    providerObservationValidUntil: string;
    providerObservationConfigurationDigest: string;
  }>(
    `select provider.provider_profile_id::text as "providerProfileId",provider.revision::text as "providerRevision",
      provider.behavior_fingerprint as "providerFingerprint",observation.observation_id::text as "providerObservationId",
      observation.observation_digest as "providerObservationDigest",observation.valid_until::text as "providerObservationValidUntil",
      observation.configuration_digest as "providerObservationConfigurationDigest"
     from control.provider_profile provider join control.provider_probe_observation observation
       on observation.provider_profile_id=provider.provider_profile_id and observation.participant_id=provider.participant_id
       and observation.privacy_domain_id=provider.privacy_domain_id and observation.observation_id=provider.qualification_observation_id
       and observation.input_digest=provider.behavior_fingerprint and observation.observed_revision+2=provider.revision
     where provider.participant_id=$1 and provider.privacy_domain_id=$2 and provider.provider_profile_id=any($3::uuid[])
       and provider.state in ('QUALIFIED','ACTIVE') and observation.state='OBSERVED' and observation.valid_until>clock_timestamp()
     for share of provider`,
    [
      scope.participantId,
      scope.privacyDomainId,
      [...new Set(targets.map((target) => target.providerProfileId))],
    ],
  );
  const providerById = new Map(
    providers.rows.map((provider) => [provider.providerProfileId, provider]),
  );
  if (
    providerById.size !== providers.rowCount ||
    targets.some(
      (target) =>
        providerById.get(target.providerProfileId)?.providerObservationConfigurationDigest !==
        digestString(target.configurationDigest),
    )
  )
    rejectRenewalSource('current_provider_configuration', id, 'PC-POLICY-2003');
  const source = policyActivationRenewalSourceSchema.parse({
    targetRef: urn(id),
    expectedRevision: occurrence.revision,
    releaseBundleId: release.releaseBundleId,
    releaseRevision: release.releaseRevision,
    policyVersionId: release.policyVersionId,
    policyGenerationId: occurrence.policyGenerationId,
    policyGenerationDigest: digestString(release.manifestDigest),
    artifactDigest: digestString(release.artifactPayloadDigest),
    compilerManifestDigest: digestString(release.schemaDigest),
    dependencyClosureDigest: digestString(release.dependencyClosureDigest),
    simulationId: release.simulationId,
    simulationInputDigest: digestString(release.simulationInputDigest),
    simulationResultDigest: digestString(release.simulationResultDigest),
    factGenerationDigest: digestString(release.factGenerationDigest),
    ...root.rows[0],
    exactCohortDigest: digestString(occurrence.exactCohortDigest),
    targets: targets.map((target) => ({
      ...providerById.get(target.providerProfileId),
      providerObservationValidUntil: new Date(
        providerById.get(target.providerProfileId)!.providerObservationValidUntil,
      ).toISOString(),
      targetId: target.targetId,
      expectedRevision: target.revision,
      expectedPredecessorDigest: target.activeGenerationDigest,
      configurationDigest: digestString(target.configurationDigest),
      providerProfileId: target.providerProfileId,
      projectionPlanId: target.projectionPlanId,
    })),
  });
  return { source, occurrence, release };
}

export async function getPolicyActivationRenewalSource(
  pool: Pool,
  scope: PublicApprovalScope,
  id: string,
): Promise<PolicyActivationRenewalSource> {
  return inScope(pool, scope, async (client) => {
    await assertActionIntent(client, scope, 'READ', ['activation-occurrences']);
    return (await policyRenewalSource(client, scope, id, scope.authority.authorityEnvelopeId))
      .source;
  });
}

/** Only the shared atomic mutation owner invokes this after current candidate,
 * maker/checker, credential, role, epoch and WebAuthn fences. */
export async function renewPolicyActivationInTransaction(
  client: PoolClient,
  context: MutationContext,
  operationId: string,
  input: RenewPolicyActivation,
): Promise<{ activationOccurrenceId: string; state: 'STAGING'; revision: string }> {
  if (
    context.catalogOperationId !== 'CFG-OP-RENEW-POLICY-ACTIVATION' ||
    context.actionIntentId !== 'ACT-POLICY_ACTIVATE_RELEASE-V1' ||
    context.expectedRevision !== input.expectedRevision ||
    urn(context.resourceId) !== input.targetRef ||
    !context.authorization.checkerPrincipalId ||
    context.authorization.checkerPrincipalId === context.authorization.principalId
  )
    throw new ContractError('PC-POLICY-2004');
  const scope: ActivationScope = {
    ...context.authorization,
    operationId,
    actionIntentId: context.actionIntentId,
    actionIntentDigest: context.actionIntentDigest,
    idempotencyKey: context.idempotencyKey,
  };
  const current = await policyRenewalSource(
    client,
    scope,
    context.resourceId,
    context.authorization.authorityEnvelopeId,
  );
  assertPolicyRenewalSource(input, current.source);
  if (current.occurrence.createdByPrincipalId !== scope.principalId)
    throw new ContractError('PC-POLICY-2004');
  const approved = await client.query<{
    approvalRequestId: string;
    approvalDecisionDigest: Buffer;
  }>(
    `select request.approval_request_id::text as "approvalRequestId",decision.decision_digest as "approvalDecisionDigest"
     from control.approval_request request join control.mutation_candidate candidate
       on candidate.participant_id=request.participant_id and candidate.privacy_domain_id=request.privacy_domain_id
         and candidate.mutation_candidate_id=request.subject_id and candidate.candidate_digest=request.subject_digest
     join control.approval_decision_record decision on decision.participant_id=request.participant_id
       and decision.privacy_domain_id=request.privacy_domain_id and decision.approval_request_id=request.approval_request_id
       and decision.decision='APPROVE' and decision.candidate_digest=request.subject_digest
     where request.participant_id=$1 and request.privacy_domain_id=$2 and request.approval_request_id=$3
       and request.subject_type='CONFIGURATION_CANDIDATE' and request.state='APPROVED' and request.expires_at>clock_timestamp()
       and request.maker_principal_id=$4 and decision.approver_principal_id=$5 and request.subject_digest=$6
       and candidate.catalog_operation_id='CFG-OP-RENEW-POLICY-ACTIVATION'
       and candidate.action_intent_id=$7 and candidate.resource_id=$8 and candidate.expected_revision=$9
       and candidate.state='APPROVED' and candidate.expires_at>clock_timestamp()`,
    [
      scope.participantId,
      scope.privacyDomainId,
      context.authorization.approvalRequestId,
      scope.principalId,
      context.authorization.checkerPrincipalId,
      digest(input),
      context.actionIntentId,
      context.resourceId,
      input.expectedRevision,
    ],
  );
  const decision = approved.rows[0];
  if (approved.rowCount !== 1 || !decision) throw new ContractError('PC-POLICY-2004');
  const proof = await stepUpProof(client, scope, context.authorization, digest(input));
  await preparePolicyActivation(
    client,
    scope,
    current.occurrence,
    { ...current.release, ...decision },
    proof,
  );
  for (const target of current.source.targets)
    await dispatchTarget(
      client,
      scope,
      current.occurrence,
      target.targetId,
      target.expectedRevision,
      target.expectedPredecessorDigest,
      'FORWARD',
      current.source.policyGenerationDigest,
    );
  const changed = await client.query<{ revision: string }>(
    `update control.policy_activation_occurrence set state='STAGING',matched_target_count=0,revision=revision+1,updated_at=clock_timestamp()
     where participant_id=$1 and privacy_domain_id=$2 and activation_occurrence_id=$3 and state='REQUESTED' and revision=$4
     returning revision::text as revision`,
    [scope.participantId, scope.privacyDomainId, context.resourceId, input.expectedRevision],
  );
  if (changed.rowCount !== 1 || !changed.rows[0]) throw new ContractError('PC-POLICY-2003');
  return {
    activationOccurrenceId: context.resourceId,
    state: 'STAGING',
    revision: changed.rows[0].revision,
  };
}

export class PolicyActivationRenewalRepository {
  private readonly mutations: AtomicConfigurationMutation;
  constructor(
    pool: Pool,
    verifier?: IdentityRuntimeVerifier,
    evidence?: ConfigurationBusinessEvidence,
  ) {
    this.mutations = new AtomicConfigurationMutation(pool, verifier, evidence);
  }
  async renew(context: MutationContext, input: RenewPolicyActivation) {
    try {
      const result = await this.mutations.execute(context, async (client, _id, operationId) => {
        const result = await renewPolicyActivationInTransaction(
          client,
          context,
          operationId,
          input,
        );
        return {
          result,
          revision: result.revision,
          outboxEventType: 'openpc.policy.activation-renewal.staging.v1',
          asynchronous: true,
        };
      });
      process.stderr.write(
        JSON.stringify({
          level: 'info',
          event: 'policy_activation_renewal_queued',
          occurrenceId: context.resourceId,
          operationId: result.operationId,
          platformContextId: input.platformContextId,
          platformEpoch: input.platformAuthorityEpoch,
          simulationId: input.simulationId,
          targetCount: input.targets.length,
          disposition: 'AWAIT_AUTHORITATIVE_WORK_AND_JOURNAL_READBACK',
        }) + '\n',
      );
      return result;
    } catch (error) {
      const code = error && typeof error === 'object' && 'code' in error ? error.code : undefined;
      process.stderr.write(
        JSON.stringify({
          level: 'warn',
          event: 'policy_activation_renewal_rejected',
          stage: 'current_governance_and_exact_source_before_dispatch',
          occurrenceId: context.resourceId,
          expectedRevision: input.expectedRevision,
          platformContextId: input.platformContextId,
          platformEpoch: input.platformAuthorityEpoch,
          simulationId: input.simulationId,
          code:
            error instanceof ContractError || error instanceof ConfigurationRepositoryError
              ? error.code
              : undefined,
          sqlstate: typeof code === 'string' && /^[0-9A-Z]{5}$/u.test(code) ? code : undefined,
          disposition: 'READBACK_OR_DIAGNOSE_BEFORE_RETRY',
        }) + '\n',
      );
      if (error instanceof ConfigurationRepositoryError) throw error;
      if (error instanceof ContractError)
        throw new ConfigurationRepositoryError(
          error.code === 'PC-POLICY-2004' ? 'PC-AUTH-0005' : 'PC-DATA-6007',
        );
      // Driver details may contain request values. Preserve SQLSTATE above;
      // the HTTP boundary receives only the closed unavailable problem.
      throw new ConfigurationRepositoryError('PC-INTEGRATION-5001');
    }
  }
}
