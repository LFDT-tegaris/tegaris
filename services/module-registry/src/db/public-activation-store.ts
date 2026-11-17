import {
  isReleaseSimulation,
  releaseSimulationSql,
} from '../domain/policy-simulation-eligibility.js';
import { createHash } from 'node:crypto';
import { activationPreview } from '../policy-activation-preview.js';

import type { Pool, PoolClient } from 'pg';
import { consumeAdministrationReservation } from './administration-resource-reservation.js';
import { resourceReadAuthoritySql } from './resource-read-authority.js';
import type { MutationContext } from '../../../control-api/src/configuration/persistence/types.js';
import { approvalAuthorityDependencies } from '../../../identity-service/src/db/approval-authority-fence.js';
import { fenceBoundAuthorities } from '../../../identity-service/src/db/authority-fence.js';

import { canonicalJson } from '../domain/digest.js';
import { ContractError } from '../domain/errors.js';
import {
  assertActionIntent,
  completeOperation,
  inScope,
  reserveOperation,
  type PublicApprovalScope,
  type PublicOperation,
} from './public-approval-store.js';

export type ActivationOccurrenceState =
  | 'REQUESTED'
  | 'STAGING'
  | 'PARTIAL'
  | 'ACTIVE_MATCHED'
  | 'FAILED'
  | 'ROLLING_BACK'
  | 'ROLLED_BACK';

export interface ActivationOccurrenceView {
  readonly activationOccurrenceId: string;
  readonly releaseBundleId: string;
  readonly targetGenerationDigest: string;
  readonly exactCohortDigest: string;
  readonly state: ActivationOccurrenceState;
  readonly matchedTargetCount: string;
  readonly totalTargetCount: string;
  readonly revision: string;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface PublicActivationListRequest {
  readonly limit: number;
  readonly state?: ActivationOccurrenceState;
  readonly snapshotAt: string;
  readonly snapshotRevision: string;
  readonly sort: 'updatedAt' | '-updatedAt';
  readonly after?: { readonly updatedAt: string; readonly id: string };
}

export interface PublicActivationPage {
  readonly items: readonly ActivationOccurrenceView[];
  readonly next?: { readonly updatedAt: string; readonly id: string };
  readonly total: string;
  readonly snapshotRevision: string;
}

export type ActivationScope = Pick<
  PublicApprovalScope,
  | 'participantId'
  | 'privacyDomainId'
  | 'principalId'
  | 'operationId'
  | 'actionIntentId'
  | 'actionIntentDigest'
  | 'idempotencyKey'
>;

export interface OccurrenceRow {
  readonly activationOccurrenceId: string;
  readonly releaseBundleId: string;
  readonly policyGenerationId: string;
  readonly createdByPrincipalId: string;
  readonly targetGenerationDigest: Buffer;
  readonly exactCohortDigest: Buffer;
  readonly state: ActivationOccurrenceState;
  readonly matchedTargetCount: string;
  readonly totalTargetCount: string;
  readonly revision: string;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface ReleaseCandidate {
  readonly releaseBundleId: string;
  readonly releaseRevision: string;
  readonly policyId: string;
  readonly policyVersionId: string;
  readonly approvalRequestId: string;
  readonly createdByPrincipalId: string;
  readonly manifestDigest: Buffer;
  readonly dependencyClosureDigest: Buffer;
  readonly schemaDigest: Buffer;
  readonly simulationId: string;
  readonly simulationInputDigest: Buffer;
  readonly simulationResultDigest: Buffer;
  readonly factGenerationDigest: Buffer;
  readonly simulationCompletedAt: string;
  readonly simulationTruthState: string;
  readonly simulationAuthorityLabel: string;
  readonly simulationResultDocument: unknown;
  readonly artifactPayloadDigest: Buffer;
  readonly checkerPrincipalId: string;
  readonly approvalDecisionDigest: Buffer;
  readonly approvalCoseSign1: Buffer;
}

export interface TargetCandidate {
  readonly state: string;
  readonly desiredGenerationDigest: string | null;
  readonly targetId: string;
  readonly activeGenerationDigest: string | null;
  readonly policyGenerationDigest: string | null;
  readonly revision: string;
  readonly configurationDigest: Buffer;
  readonly providerProfileId: string;
  readonly projectionPlanId: string;
}

function targetMatches(target: TargetCandidate, policyDigest: string): boolean {
  return (
    target.state === 'ACTIVE_MATCHED' &&
    target.activeGenerationDigest !== null &&
    target.activeGenerationDigest === target.desiredGenerationDigest &&
    target.policyGenerationDigest === policyDigest
  );
}

const digest = (value: unknown) => createHash('sha256').update(canonicalJson(value)).digest();
const bytes = (value: string) => Buffer.from(value.slice('sha256:'.length), 'hex');
const digestString = (value: Buffer) => `sha256:${value.toString('hex')}`;
const timestamp = (value: string | Date) =>
  new Date(value).toISOString().replace(/\.([0-9]{3})Z$/u, '.$1000Z');
const urn = (id: string) => `urn:openpc:resource:${id}`;

const selectOccurrence = `select occurrence.activation_occurrence_id::text as "activationOccurrenceId",
       occurrence.release_bundle_id::text as "releaseBundleId",
       occurrence.policy_generation_id::text as "policyGenerationId",
       occurrence.created_by_principal_id::text as "createdByPrincipalId",
       occurrence.target_generation_digest as "targetGenerationDigest",
       occurrence.exact_cohort_digest as "exactCohortDigest",occurrence.state,
       occurrence.matched_target_count::text as "matchedTargetCount",
       occurrence.total_target_count::text as "totalTargetCount",
       occurrence.revision::text as revision,occurrence.created_at::text as "createdAt",
       occurrence.updated_at::text as "updatedAt"
  from control.policy_activation_occurrence occurrence`;

function view(row: OccurrenceRow): ActivationOccurrenceView {
  return {
    activationOccurrenceId: urn(row.activationOccurrenceId),
    releaseBundleId: urn(row.releaseBundleId),
    targetGenerationDigest: digestString(row.targetGenerationDigest),
    exactCohortDigest: digestString(row.exactCohortDigest),
    state: row.state,
    matchedTargetCount: row.matchedTargetCount,
    totalTargetCount: row.totalTargetCount,
    revision: row.revision,
    createdAt: timestamp(row.createdAt),
    updatedAt: timestamp(row.updatedAt),
  };
}

export async function occurrenceRow(
  client: PoolClient,
  scope: ActivationScope,
  id: string,
  lock = false,
): Promise<OccurrenceRow> {
  const selected = await client.query<OccurrenceRow>(
    `${selectOccurrence} where occurrence.participant_id=$1 and occurrence.privacy_domain_id=$2
       and occurrence.activation_occurrence_id=$3${lock ? ' for update of occurrence' : ''}`,
    [scope.participantId, scope.privacyDomainId, id],
  );
  const row = selected.rows[0];
  if (selected.rowCount !== 1 || row === undefined) throw new ContractError('PC-POLICY-2001');
  return row;
}

export async function readPublicActivationPreview(
  pool: Pool,
  scope: PublicApprovalScope,
  releaseBundleId: string,
) {
  return inScope(pool, scope, async (client) => {
    await assertActionIntent(client, scope, 'READ', ['release-bundles']);
    // A complete cohort preview must not expose hidden target IDs, readiness or
    // counts. Filtering would fabricate a smaller activation cohort instead.
    const admitted = await client.query<{ allowed: boolean | null }>(
      `select bool_and(${resourceReadAuthoritySql('ACT-RUNTIME_TARGETS_READ_RESOURCE-V1', 'target.runtime_target_id')}) as allowed
       from control.runtime_target target
       where target.participant_id=$1 and target.privacy_domain_id=$2 and $3::boolean`,
      [
        scope.participantId,
        scope.privacyDomainId,
        true,
        scope.principalId,
        scope.authority.sessionId,
      ],
    );
    if (admitted.rows[0]?.allowed !== true) throw new ContractError('PC-POLICY-2001');
    const release = await releaseCandidate(client, scope, releaseBundleId);
    return activationPreview(release, await exactTargets(client, scope));
  });
}

export async function releaseCandidate(
  client: PoolClient,
  scope: ActivationScope,
  releaseBundleId: string,
  expectedManifest?: Buffer,
): Promise<ReleaseCandidate> {
  const selected = await client.query<ReleaseCandidate>(
    `select release.release_bundle_id::text as "releaseBundleId",
            release.revision::text as "releaseRevision",
            version.policy_id::text as "policyId",
            release.policy_version_id::text as "policyVersionId",
            release.approval_request_id::text as "approvalRequestId",
            release.created_by_principal_id::text as "createdByPrincipalId",
            release.manifest_digest as "manifestDigest",
            release.dependency_closure_digest as "dependencyClosureDigest",
            version.schema_digest as "schemaDigest",simulation.simulation_id::text as "simulationId",
            simulation.input_digest as "simulationInputDigest",
            simulation.result_digest as "simulationResultDigest",
            simulation.fact_generation_digest as "factGenerationDigest",
            simulation.completed_at::text as "simulationCompletedAt",
            simulation.truth_state as "simulationTruthState",
            simulation.authority_label as "simulationAuthorityLabel",
            simulation.result_document as "simulationResultDocument",
            artifact.payload_digest as "artifactPayloadDigest",
            decision.approver_principal_id::text as "checkerPrincipalId",
            decision.decision_digest as "approvalDecisionDigest",
            decision.cose_sign1 as "approvalCoseSign1"
       from control.policy_release_bundle release
       join control.policy_version version
         on (version.participant_id,version.privacy_domain_id,version.policy_version_id)=
            (release.participant_id,release.privacy_domain_id,release.policy_version_id)
       join control.policy_artifact artifact
         on artifact.participant_id=version.participant_id
        and artifact.privacy_domain_id=version.privacy_domain_id
        and artifact.semantic_digest=version.semantic_digest
        and artifact.dependency_closure_digest=release.dependency_closure_digest
       join control.approval_request approval
         on approval.participant_id=release.participant_id
        and approval.privacy_domain_id=release.privacy_domain_id
        and approval.approval_request_id=release.approval_request_id
        and approval.subject_type='POLICY_VERSION' and approval.subject_id=version.policy_version_id
        and approval.subject_digest=release.manifest_digest and approval.state='APPROVED'
        and approval.maker_principal_id=release.created_by_principal_id
       join control.approval_decision_record decision
         on decision.participant_id=approval.participant_id
        and decision.privacy_domain_id=approval.privacy_domain_id
        and decision.approval_request_id=approval.approval_request_id
        and decision.decision='APPROVE' and decision.candidate_digest=approval.subject_digest
        and decision.approver_principal_id<>approval.maker_principal_id
       join lateral (
         select simulation_id,input_digest,result_digest,fact_generation_digest,
                dependency_closure_digest,completed_at,truth_state,authority_label,result_document
           from control.policy_simulation simulation
          where participant_id=release.participant_id
            and privacy_domain_id=release.privacy_domain_id
            and policy_version_id=release.policy_version_id
            and ${releaseSimulationSql('simulation')} and authority_label='SIMULATION_ONLY'
          order by completed_at desc,simulation_id desc limit 1
       ) simulation on simulation.dependency_closure_digest=release.dependency_closure_digest
      where release.participant_id=$1 and release.privacy_domain_id=$2
        and release.release_bundle_id=$3 and release.state in ('PUBLISHED','ACTIVE')
        and release.approval_request_id is not null
        and ($4::bytea is null or release.manifest_digest=$4)
      order by simulation.completed_at desc limit 1`,
    [scope.participantId, scope.privacyDomainId, releaseBundleId, expectedManifest ?? null],
  );
  const row = selected.rows[0];
  if (
    selected.rowCount !== 1 ||
    row === undefined ||
    !isReleaseSimulation({
      truthState: row.simulationTruthState,
      authorityLabel: row.simulationAuthorityLabel,
      resultDocument: row.simulationResultDocument,
      inputDigest: row.simulationInputDigest,
      resultDigest: row.simulationResultDigest,
    })
  )
    throw new ContractError('PC-POLICY-2003');
  return row;
}

export async function exactTargets(
  client: PoolClient,
  scope: ActivationScope,
): Promise<readonly TargetCandidate[]> {
  await client.query(
    "select pg_advisory_xact_lock(hashtextextended('openpc-policy-generations:'||$1::text||':'||$2::text,0))",
    [scope.participantId, scope.privacyDomainId],
  );
  const unavailable = await client.query(
    `select 1 from control.runtime_target where participant_id=$1 and privacy_domain_id=$2
      and state not in ('OFFLINE','QUARANTINED','INCOMPATIBLE')
      and not openpc.runtime_target_discovery_current(participant_id,privacy_domain_id,runtime_target_id) limit 1`,
    [scope.participantId, scope.privacyDomainId],
  );
  if (unavailable.rowCount !== 0) throw new ContractError('PC-POLICY-2003');
  const targets = await client.query<TargetCandidate>(
    `select target.runtime_target_id::text as "targetId",target.state,
            target.desired_generation_digest as "desiredGenerationDigest",
            target.active_generation_digest as "activeGenerationDigest",
            target.policy_generation_digest as "policyGenerationDigest",target.revision::text as revision,
            configuration.configuration_digest as "configurationDigest",
            provider.provider_profile_id::text as "providerProfileId",
            projection.projection_plan_id::text as "projectionPlanId"
       from control.runtime_target target
       join lateral (
         select decode(min(encode(configuration.configuration_digest,'hex')),'hex')
                as configuration_digest
           from control.module_installation installation
           join control.module_version version on version.module_version_id=installation.module_version_id
           join control.module_registration module on module.module_id=version.module_id
           join control.runtime_configuration_input_current_metadata configuration
             on configuration.module_installation_id=installation.module_installation_id
            and configuration.active=true
          where installation.participant_id=target.participant_id
            and installation.privacy_domain_id=target.privacy_domain_id
            and installation.state='ENABLED' and module.module_id='pc.config.assets'
         having count(*)=1
       ) configuration on true
       join lateral (
         select min(provider_profile_id::text)::uuid as provider_profile_id
           from control.provider_profile
          where participant_id=target.participant_id
            and privacy_domain_id=target.privacy_domain_id
            and state in ('QUALIFIED','ACTIVE')
         having count(*)=1
       ) provider on true
       join lateral (
         select min(projection.projection_plan_id::text)::uuid as projection_plan_id
           from control.projection_plan projection
           join control.indexer_profile indexer
             on indexer.indexer_profile_id=projection.indexer_profile_id
            and indexer.participant_id=projection.participant_id
            and indexer.privacy_domain_id=projection.privacy_domain_id
            and indexer.state in ('QUALIFIED','ACTIVE')
          where projection.participant_id=target.participant_id
            and projection.privacy_domain_id=target.privacy_domain_id
            and projection.state in ('VALIDATED','RUNNING') and projection.readiness='READY'
         having count(*)=1
       ) projection on true
      where target.participant_id=$1 and target.privacy_domain_id=$2
        and target.state not in ('OFFLINE','QUARANTINED','INCOMPATIBLE')
        and openpc.runtime_target_discovery_current(target.participant_id,target.privacy_domain_id,target.runtime_target_id)
      order by target.runtime_target_id for update of target`,
    [scope.participantId, scope.privacyDomainId],
  );
  if (targets.rowCount === 0) throw new ContractError('PC-POLICY-2003');
  return targets.rows;
}

export function cohortDigest(targets: readonly TargetCandidate[]): Buffer {
  return digest(
    targets.map((target) => ({
      runtimeTargetId: urn(target.targetId),
      expectedPredecessorDigest: target.activeGenerationDigest,
    })),
  );
}

function fleetReadinessReceipt(targets: readonly TargetCandidate[]): Buffer {
  return digest(
    targets.map((target) => ({
      runtimeTargetId: urn(target.targetId),
      targetRevision: target.revision,
      activeGenerationDigest: target.activeGenerationDigest,
      policyGenerationDigest: target.policyGenerationDigest,
      configurationDigest: digestString(target.configurationDigest),
      providerProfileId: urn(target.providerProfileId),
      projectionPlanId: urn(target.projectionPlanId),
    })),
  );
}

function releaseScopeDigest(scope: ActivationScope, release: ReleaseCandidate): Buffer {
  return digest({
    participantId: scope.participantId,
    privacyDomainId: scope.privacyDomainId,
    policySetId: `urn:openpc:policy-set:${release.policyId}`,
  });
}

async function insertGeneration(
  client: PoolClient,
  scope: PublicApprovalScope,
  release: ReleaseCandidate,
  targets: readonly TargetCandidate[],
): Promise<string> {
  const policyScopeDigest = releaseScopeDigest(scope, release);
  const settled =
    targets.length > 0 &&
    targets.every(
      (target) =>
        target.state === 'ACTIVE_MATCHED' &&
        target.activeGenerationDigest !== null &&
        target.activeGenerationDigest === target.desiredGenerationDigest &&
        target.policyGenerationDigest === digestString(release.manifestDigest),
    );
  const existing = await client.query<{ readonly id: string; readonly reusable: boolean }>(
    `select generation.policy_generation_id::text as id,
       (
         (generation.state='PREPARED' and not generation.active
           and not exists (select 1 from control.policy_activation_occurrence occurrence
                            where occurrence.policy_generation_id=generation.policy_generation_id
                              and occurrence.state<>'FAILED')
           and not exists (
             select 1 from control.policy_activation activation
              where activation.policy_generation_id=generation.policy_generation_id
                and not (
                  activation.state in ('PREPARED','FAILED_FENCED')
                  and activation.activated_at is null
                  and exists (
                    select 1 from control.policy_activation_occurrence occurrence
                     where occurrence.activation_occurrence_id=activation.policy_activation_id
                       and occurrence.policy_generation_id=generation.policy_generation_id
                       and occurrence.state='FAILED'
                  )
                  and exists (
                    select 1 from control.policy_activation_occurrence_target target
                     where target.activation_occurrence_id=activation.policy_activation_id
                       and target.phase='FORWARD'
                  )
                  and not exists (
                    select 1 from control.policy_activation_occurrence_target target
                     join control.configuration_work work
                       on work.configuration_work_id=target.configuration_work_id
                    where target.activation_occurrence_id=activation.policy_activation_id
                      and target.phase='FORWARD'
                      and (target.state<>'FAILED' or work.state<>'FAILED')
                  )
                )
           ))
         or (generation.state='ACTIVE' and generation.active and $12::boolean
           and generation.policy_version_id=$4
           and exists (select 1 from control.policy_simulation simulation
             where simulation.simulation_id=$5 and simulation.participant_id=$1 and simulation.privacy_domain_id=$2
               and simulation.policy_version_id=$4 and ${releaseSimulationSql('simulation')})
       and generation.approval_request_id=$6 and generation.scope_digest=$7
       and generation.fact_generation_digest=$8 and generation.artifact_digest=$9
       and generation.compiler_manifest_digest=$10 and generation.dependency_closure_digest=$11
           and not exists (select 1 from control.policy_generation other
                            where other.participant_id=$1 and other.privacy_domain_id=$2
                              and other.scope_digest=$7 and other.active
                              and other.policy_generation_id<>generation.policy_generation_id)
           and not exists (select 1 from control.policy_activation_occurrence occurrence
                            where occurrence.policy_generation_id=generation.policy_generation_id
                              and occurrence.state in ('REQUESTED','STAGING','PARTIAL','ROLLING_BACK'))
           and exists (
             select 1 from control.policy_activation_occurrence prior
              where prior.participant_id=$1 and prior.privacy_domain_id=$2
                and prior.policy_generation_id=generation.policy_generation_id
                and prior.release_bundle_id=$14 and prior.state='ACTIVE_MATCHED'
                and (select count(*) from control.policy_activation_occurrence_target cohort
                      where cohort.activation_occurrence_id=prior.activation_occurrence_id
                        and cohort.participant_id=$1 and cohort.privacy_domain_id=$2
                        and cohort.phase='FORWARD')=cardinality($13::uuid[])
                and not exists (select 1 from control.policy_activation_occurrence_target cohort
                                 where cohort.activation_occurrence_id=prior.activation_occurrence_id
                                   and cohort.phase='FORWARD'
                                   and (cohort.participant_id<>$1 or cohort.privacy_domain_id<>$2
                                     or not(cohort.runtime_target_id=any($13::uuid[]))))
           ))
       ) as reusable
       from control.policy_generation generation
      where generation.participant_id=$1 and generation.privacy_domain_id=$2
        and generation.generation_digest=$3 for update of generation`,
    [
      scope.participantId,
      scope.privacyDomainId,
      release.manifestDigest,
      release.policyVersionId,
      // Historical simulation is part of artifact provenance. A later successful
      // simulation is bound separately by the fresh governed activation intent.
      release.simulationId,
      release.approvalRequestId,
      policyScopeDigest,
      release.factGenerationDigest,
      release.artifactPayloadDigest,
      release.schemaDigest,
      release.dependencyClosureDigest,
      settled,
      targets.map((target) => target.targetId),
      release.releaseBundleId,
    ],
  );
  const previous = existing.rows[0];
  if (previous !== undefined) {
    if (!previous.reusable) throw new ContractError('PC-POLICY-2003');
    return previous.id;
  }
  const inserted = await client.query<{ readonly id: string }>(
    `insert into control.policy_generation
       (participant_id,privacy_domain_id,policy_version_id,simulation_id,approval_request_id,
        generation,scope_digest,generation_digest,fact_generation_digest,artifact_digest,
        compiler_manifest_digest,dependency_closure_digest,state)
     select $1,$2,$3,$4,$5,coalesce(max(generation),0)+1,$6,$7,$8,$9,$10,$11,'PREPARED'
       from control.policy_generation
      where participant_id=$1 and privacy_domain_id=$2 and policy_version_id=$3
     returning policy_generation_id::text as id`,
    [
      scope.participantId,
      scope.privacyDomainId,
      release.policyVersionId,
      release.simulationId,
      release.approvalRequestId,
      policyScopeDigest,
      release.manifestDigest,
      release.factGenerationDigest,
      release.artifactPayloadDigest,
      release.schemaDigest,
      release.dependencyClosureDigest,
    ],
  );
  const row = inserted.rows[0];
  if (inserted.rowCount !== 1 || row === undefined) throw new ContractError('PC-POLICY-2005');
  return row.id;
}

export async function createPublicActivationOccurrence(
  pool: Pool,
  scope: PublicApprovalScope,
  input: {
    readonly releaseBundleId: string;
    readonly targetGenerationDigest: string;
    readonly matchedTargetCount: string;
    readonly totalTargetCount: string;
    readonly request: unknown;
    readonly resourceReservationId?: string;
    readonly activationPreviewDigest?: string;
  },
): Promise<PublicOperation> {
  return inScope(pool, scope, async (client) => {
    const intent = await assertActionIntent(client, scope, 'CREATE', ['activation-occurrences']);
    const replay = await reserveOperation(client, scope, digest(input.request), '0');
    if (replay !== undefined) return replay;
    const release = await releaseCandidate(
      client,
      scope,
      input.releaseBundleId,
      bytes(input.targetGenerationDigest),
    );
    const targets = await exactTargets(client, scope);
    if (
      input.activationPreviewDigest !== undefined &&
      input.activationPreviewDigest !== activationPreview(release, targets).activationPreviewDigest
    ) {
      process.stderr.write(
        JSON.stringify({
          level: 'warn',
          event: 'policy_occurrence_stage',
          stage: 'current_cohort_preview',
          participantId: scope.participantId,
          releaseBundleId: release.releaseBundleId,
          releaseRevision: release.releaseRevision,
          expectedPreviewDigest: input.activationPreviewDigest,
          observedPreviewDigest: activationPreview(release, targets).activationPreviewDigest,
          disposition: 'STALE_PREVIEW_NO_EFFECT',
        }) + '\n',
      );
      throw new ContractError('PC-POLICY-2003');
    }
    const matched = targets.filter((target) =>
      targetMatches(target, input.targetGenerationDigest),
    ).length;
    if (
      input.targetGenerationDigest !== digestString(release.manifestDigest) ||
      input.totalTargetCount !== String(targets.length) ||
      input.matchedTargetCount !== String(matched)
    ) {
      throw new ContractError('PC-POLICY-2003');
    }
    const generationId = await insertGeneration(client, scope, release, targets);
    const exactCohort = cohortDigest(targets);
    const reservedId =
      input.resourceReservationId === undefined
        ? undefined
        : await consumeAdministrationReservation(client, scope, input.resourceReservationId, {
            purpose: 'POLICY_ACTIVATION_OCCURRENCE',
            businessActionIntentId: 'ACT-POLICY_ACTIVATE_RELEASE-V1',
            businessResourceId: release.releaseBundleId,
            expectedBusinessRevision: release.releaseRevision,
            checkerPrincipalId: release.checkerPrincipalId,
          });
    const inserted = await client.query<{ readonly id: string }>(
      `insert into control.policy_activation_occurrence
         (participant_id,privacy_domain_id,release_bundle_id,policy_generation_id,
          created_by_principal_id,target_generation_digest,exact_cohort_digest,
          matched_target_count,total_target_count,activation_occurrence_id)
       values($1,$2,$3,$4,$5,$6,$7,$8,$9,coalesce($10::uuid,uuidv7()))
       returning activation_occurrence_id::text as id`,
      [
        scope.participantId,
        scope.privacyDomainId,
        release.releaseBundleId,
        generationId,
        scope.principalId,
        release.manifestDigest,
        exactCohort,
        matched,
        targets.length,
        reservedId ?? null,
      ],
    );
    const occurrence = inserted.rows[0];
    if (inserted.rowCount !== 1 || occurrence === undefined)
      throw new ContractError('PC-POLICY-2005');
    for (const target of targets) {
      await client.query(
        `insert into control.policy_activation_occurrence_target
           (activation_occurrence_id,participant_id,privacy_domain_id,runtime_target_id,
            phase,expected_target_revision,expected_predecessor_digest,state)
         values($1,$2,$3,$4,'FORWARD',$5,$6,$7)`,
        [
          occurrence.id,
          scope.participantId,
          scope.privacyDomainId,
          target.targetId,
          target.revision,
          target.activeGenerationDigest,
          targetMatches(target, input.targetGenerationDigest) ? 'ACTIVE_MATCHED' : 'REQUESTED',
        ],
      );
    }
    return completeOperation(client, scope, intent, occurrence.id, '1');
  });
}

export async function getPublicActivationOccurrence(
  pool: Pool,
  scope: PublicApprovalScope,
  id: string,
): Promise<ActivationOccurrenceView> {
  return inScope(pool, scope, async (client) => {
    await assertActionIntent(client, scope, 'READ', ['activation-occurrences']);
    return view(await occurrenceRow(client, scope, id));
  });
}

export async function listPublicActivationOccurrences(
  pool: Pool,
  scope: PublicApprovalScope,
  request: PublicActivationListRequest,
): Promise<PublicActivationPage> {
  return inScope(pool, scope, async (client) => {
    await assertActionIntent(client, scope, 'READ', ['activation-occurrences']);
    const values: unknown[] = [
      scope.participantId,
      scope.privacyDomainId,
      request.snapshotAt,
      scope.principalId,
      scope.authority.sessionId,
    ];
    const where = [
      'occurrence.participant_id=$1',
      'occurrence.privacy_domain_id=$2',
      'occurrence.updated_at <= $3::timestamptz',
      resourceReadAuthoritySql(
        'ACT-ACTIVATION_OCCURRENCES_READ_RESOURCE-V1',
        'occurrence.activation_occurrence_id',
      ),
    ];
    if (request.state !== undefined) {
      values.push(request.state);
      where.push(`occurrence.state=$${values.length}`);
    }
    const count = await client.query<{ readonly total: string }>(
      `select count(*)::text as total from control.policy_activation_occurrence occurrence
        where ${where.join(' and ')}`,
      values,
    );
    if (request.after !== undefined) {
      values.push(request.after.updatedAt, request.after.id);
      where.push(
        `(occurrence.updated_at,occurrence.activation_occurrence_id) ${request.sort === '-updatedAt' ? '<' : '>'} ` +
          `($${values.length - 1}::timestamptz,$${values.length}::uuid)`,
      );
    }
    values.push(request.limit + 1);
    const direction = request.sort === '-updatedAt' ? 'desc' : 'asc';
    const selected = await client.query<OccurrenceRow>(
      `${selectOccurrence} where ${where.join(' and ')}
       order by occurrence.updated_at ${direction},occurrence.activation_occurrence_id ${direction}
       limit $${values.length}`,
      values,
    );
    const hasNext = selected.rows.length > request.limit;
    const rows = selected.rows.slice(0, request.limit);
    const last = hasNext ? rows.at(-1) : undefined;
    return {
      items: rows.map(view),
      ...(last === undefined
        ? {}
        : { next: { updatedAt: timestamp(last.updatedAt), id: last.activationOccurrenceId } }),
      total: count.rows[0]?.total ?? '0',
      snapshotRevision: request.snapshotRevision,
    };
  });
}

export async function updatePublicActivationOccurrence(
  pool: Pool,
  scope: PublicApprovalScope,
  id: string,
  expectedRevision: string,
  replacementDigest: string,
  request: unknown,
): Promise<PublicOperation> {
  return inScope(pool, scope, async (client) => {
    const intent = await assertActionIntent(client, scope, 'UPDATE', ['activation-occurrences']);
    const replay = await reserveOperation(client, scope, digest(request), expectedRevision);
    if (replay !== undefined) return replay;
    const current = await occurrenceRow(client, scope, id, true);
    if (
      current.state !== 'REQUESTED' ||
      current.revision !== expectedRevision ||
      current.createdByPrincipalId !== scope.principalId ||
      digestString(current.targetGenerationDigest) === replacementDigest
    ) {
      throw new ContractError('PC-POLICY-2003');
    }
    const replacementRelease = await client.query<{ readonly id: string }>(
      `select release_bundle_id::text as id from control.policy_release_bundle
        where participant_id=$1 and privacy_domain_id=$2 and state='PUBLISHED'
          and manifest_digest=$3 order by published_at desc limit 2`,
      [scope.participantId, scope.privacyDomainId, bytes(replacementDigest)],
    );
    const replacement = replacementRelease.rows[0];
    if (replacementRelease.rowCount !== 1 || replacement === undefined)
      throw new ContractError('PC-POLICY-2003');
    const release = await releaseCandidate(client, scope, replacement.id, bytes(replacementDigest));
    const targets = await exactTargets(client, scope);
    const exactCohort = cohortDigest(targets);
    const generationId = await insertGeneration(client, scope, release, targets);
    await client.query(
      `delete from control.policy_activation_occurrence_target
        where participant_id=$1 and privacy_domain_id=$2 and activation_occurrence_id=$3`,
      [scope.participantId, scope.privacyDomainId, id],
    );
    for (const target of targets) {
      await client.query(
        `insert into control.policy_activation_occurrence_target
           (activation_occurrence_id,participant_id,privacy_domain_id,runtime_target_id,
            phase,expected_target_revision,expected_predecessor_digest,state)
         values($1,$2,$3,$4,'FORWARD',$5,$6,$7)`,
        [
          id,
          scope.participantId,
          scope.privacyDomainId,
          target.targetId,
          target.revision,
          target.activeGenerationDigest,
          targetMatches(target, replacementDigest) ? 'ACTIVE_MATCHED' : 'REQUESTED',
        ],
      );
    }
    const matched = targets.filter((target) => targetMatches(target, replacementDigest)).length;
    const changed = await client.query<{ readonly revision: string }>(
      `update control.policy_activation_occurrence
          set release_bundle_id=$4,policy_generation_id=$5,target_generation_digest=$6,
              exact_cohort_digest=$7,matched_target_count=$8,total_target_count=$9,
              revision=revision+1,updated_at=clock_timestamp()
        where participant_id=$1 and privacy_domain_id=$2 and activation_occurrence_id=$3
          and state='REQUESTED' and revision=$10
        returning revision::text as revision`,
      [
        scope.participantId,
        scope.privacyDomainId,
        id,
        release.releaseBundleId,
        generationId,
        release.manifestDigest,
        exactCohort,
        matched,
        targets.length,
        expectedRevision,
      ],
    );
    const row = changed.rows[0];
    if (changed.rowCount !== 1 || row === undefined) throw new ContractError('PC-POLICY-2002');
    return completeOperation(client, scope, intent, id, row.revision);
  });
}

interface CommandAuthority {
  readonly sessionId: string;
  readonly participantEpoch: string;
  readonly principalEpoch: string;
}

interface StepUpProof {
  readonly mfaChallengeId: string;
  readonly assertionBindingDigest: Buffer;
  readonly evidenceCbor: Buffer;
  readonly evidenceDigest: Buffer;
  readonly coseSign1: Buffer;
  readonly signerCredentialId: string;
}

export async function stepUpProof(
  client: PoolClient,
  scope: ActivationScope,
  authority: CommandAuthority,
  inputDigest: Buffer,
): Promise<StepUpProof> {
  const selected = await client.query<StepUpProof>(
    `select challenge.mfa_challenge_id::text as "mfaChallengeId",
            evidence.webauthn_assertion_binding_digest as "assertionBindingDigest",
            evidence.evidence_cbor as "evidenceCbor",evidence.evidence_digest as "evidenceDigest",
            evidence.cose_sign1 as "coseSign1",
            evidence.signer_credential_id::text as "signerCredentialId"
       from control.mfa_challenge challenge
       join control.mutation_evidence evidence
         on evidence.participant_id=challenge.participant_id
        and evidence.privacy_domain_id=$2 and evidence.principal_id=challenge.principal_id
        and evidence.mfa_challenge_id=challenge.mfa_challenge_id
        and evidence.catalog_operation_id='ID-OP-WEBAUTHN-VERIFY'
        and evidence.aggregate_type='webauthn-verification'
        and evidence.action_intent_id='ACT-IDENTITY_UPDATE_STEP_UP-V1'
        and evidence.webauthn_assertion_binding_digest is not null
       join control.idempotency_record verification
         on verification.participant_id=evidence.participant_id
        and verification.operation_id=evidence.operation_id
        and verification.catalog_operation_id=evidence.catalog_operation_id
        and verification.terminal_state='COMMITTED'
        and verification.input_digest=evidence.candidate_digest
        and verification.webauthn_assertion_binding_digest=evidence.webauthn_assertion_binding_digest
       join control.outbox_event verified_event
         on verified_event.participant_id=evidence.participant_id
        and verified_event.aggregate_type=evidence.aggregate_type
        and verified_event.aggregate_id=evidence.aggregate_id
        and verified_event.event_type='openpc.identity.webauthn-verification.mutation.committed.v1'
        and verified_event.webauthn_assertion_binding_digest=evidence.webauthn_assertion_binding_digest
        and verified_event.payload_digest=evidence.evidence_digest
       join control.credential credential
         on credential.participant_id=evidence.participant_id
        and credential.principal_id=evidence.principal_id
        and credential.credential_id=evidence.signer_credential_id
        and credential.kind='WEBAUTHN' and credential.state='ACTIVE'
        and credential.valid_from<=clock_timestamp()
        and (credential.valid_until is null or credential.valid_until>clock_timestamp())
      where challenge.participant_id=$1 and challenge.session_id=$3
        and challenge.principal_id=$4 and challenge.action_intent_id=$5
        and challenge.resource_digest=$6 and challenge.consumed_at is not null
        and challenge.consumed_at>=clock_timestamp()-interval '5 minutes'
        and challenge.expires_at>clock_timestamp()
        and (challenge.used_at is null or challenge.used_operation_id=$7)
        and evidence.bound_participant_epoch=$8 and evidence.bound_principal_epoch=$9
        and evidence.occurred_at>=challenge.consumed_at
        and evidence.occurred_at>=clock_timestamp()-interval '5 minutes'
      order by challenge.consumed_at desc,challenge.mfa_challenge_id desc limit 1
      for update of challenge`,
    [
      scope.participantId,
      scope.privacyDomainId,
      authority.sessionId,
      scope.principalId,
      scope.actionIntentId,
      inputDigest,
      scope.operationId,
      authority.participantEpoch,
      authority.principalEpoch,
    ],
  );
  const row = selected.rows[0];
  if (selected.rowCount !== 1 || row === undefined) throw new ContractError('PC-POLICY-2004');
  return row;
}

function expectedCommandDigest(
  actionIntentId: string,
  id: string,
  occurrence: OccurrenceRow,
  expectedRevision: string,
): Buffer {
  return digest({
    actionIntentId,
    targetRef: urn(id),
    targetGenerationDigest: digestString(occurrence.targetGenerationDigest),
    exactCohortDigest: digestString(occurrence.exactCohortDigest),
    expectedRevision,
  });
}

async function recordControlEvent(
  client: PoolClient,
  scope: ActivationScope,
  occurrenceId: string,
  eventType: string,
  proof: StepUpProof,
): Promise<void> {
  const sequence = await client.query<{ readonly value: string }>(
    `insert into control.outbox_aggregate_head
       (participant_id,aggregate_type,aggregate_id,last_sequence)
     values($1,'policy-activation-occurrence',$2,1)
     on conflict (participant_id,aggregate_type,aggregate_id) do update
       set last_sequence=control.outbox_aggregate_head.last_sequence+1,
           updated_at=clock_timestamp()
     returning last_sequence::text as value`,
    [scope.participantId, occurrenceId],
  );
  const value = sequence.rows[0]?.value;
  if (value === undefined) throw new ContractError('PC-POLICY-2005');
  await client.query(
    `insert into control.outbox_event
       (participant_id,privacy_domain_id,event_id,event_type,aggregate_type,aggregate_id,
        aggregate_sequence,payload_cbor,payload_digest,cose_sign1,
        webauthn_assertion_binding_digest,occurred_at)
     values($1,$2,uuidv7(),$3,'policy-activation-occurrence',$4,$5,$6,$7,$8,$9,
            clock_timestamp())`,
    [
      scope.participantId,
      scope.privacyDomainId,
      eventType,
      occurrenceId,
      value,
      proof.evidenceCbor,
      proof.evidenceDigest,
      proof.coseSign1,
      proof.assertionBindingDigest,
    ],
  );
}

interface DispatchCandidate {
  readonly configurationDigest: string;
  readonly providerProfileId: string;
  readonly projectionPlanId: string;
  readonly targetRevision: string;
  readonly activeGenerationDigest: string | null;
}

export async function dispatchTarget(
  client: PoolClient,
  scope: ActivationScope,
  occurrence: OccurrenceRow,
  targetId: string,
  expectedTargetRevision: string,
  expectedPredecessorDigest: string | null,
  phase: 'FORWARD' | 'ROLLBACK',
  policyGenerationDigest: string,
): Promise<void> {
  const selected = await client.query<DispatchCandidate>(
    `select 'sha256:'||encode(configuration.configuration_digest,'hex') as "configurationDigest",
            provider.provider_profile_id::text as "providerProfileId",
            projection.projection_plan_id::text as "projectionPlanId",
            target.revision::text as "targetRevision",
            target.active_generation_digest as "activeGenerationDigest"
       from control.runtime_target target
       join control.module_installation installation
         on installation.participant_id=target.participant_id
        and installation.privacy_domain_id=target.privacy_domain_id
        and installation.state='ENABLED'
       join control.module_version version on version.module_version_id=installation.module_version_id
       join control.module_registration module on module.module_id=version.module_id
        and module.module_id='pc.config.assets'
       join control.runtime_configuration_input_current_metadata configuration
         on configuration.module_installation_id=installation.module_installation_id
        and configuration.active=true
       join control.provider_profile provider on provider.participant_id=target.participant_id
        and provider.privacy_domain_id=target.privacy_domain_id
        and provider.state in ('QUALIFIED','ACTIVE')
       join control.projection_plan projection on projection.participant_id=target.participant_id
        and projection.privacy_domain_id=target.privacy_domain_id
        and projection.state in ('VALIDATED','RUNNING') and projection.readiness='READY'
       join control.indexer_profile indexer on indexer.indexer_profile_id=projection.indexer_profile_id
        and indexer.participant_id=projection.participant_id
        and indexer.privacy_domain_id=projection.privacy_domain_id
        and indexer.state in ('QUALIFIED','ACTIVE')
      where target.participant_id=$1 and target.privacy_domain_id=$2
        and target.runtime_target_id=$3 and target.revision=$4
        and target.state not in ('OFFLINE','QUARANTINED','INCOMPATIBLE')
        and target.active_generation_digest is not distinct from $5
        and openpc.runtime_target_discovery_current(target.participant_id,target.privacy_domain_id,target.runtime_target_id)
      limit 2 for update of target`,
    [
      scope.participantId,
      scope.privacyDomainId,
      targetId,
      expectedTargetRevision,
      expectedPredecessorDigest,
    ],
  );
  const candidate = selected.rows[0];
  if (selected.rowCount !== 1 || candidate === undefined) throw new ContractError('PC-POLICY-2003');
  const generationDigest = digestString(
    digest({
      configurationDigest: candidate.configurationDigest,
      policyGenerationDigest,
      providerProfileId: candidate.providerProfileId,
      projectionPlanId: candidate.projectionPlanId,
      runtimeTargetId: targetId,
    }),
  );
  const generation = await client.query<{ readonly id: string }>(
    `insert into control.runtime_configuration_generation
       (participant_id,privacy_domain_id,runtime_target_id,provider_profile_id,projection_plan_id,
        predecessor_digest,generation_digest,policy_generation_digest,state)
     values($1,$2,$3,$4,$5,$6,$7,$8,'ACTIVATING')
     returning runtime_configuration_generation_id::text as id`,
    [
      scope.participantId,
      scope.privacyDomainId,
      targetId,
      candidate.providerProfileId,
      candidate.projectionPlanId,
      expectedPredecessorDigest,
      generationDigest,
      policyGenerationDigest,
    ],
  );
  const generationId = generation.rows[0]?.id;
  if (generationId === undefined) throw new ContractError('PC-POLICY-2005');
  // Releasing or rolling back the same content still installs fresh custody.
  // Bind the proxy acknowledgement to this durable activation instance.
  const xdsDigest = digestString(
    digest({ generationDigest, generationId, runtimeTargetId: targetId }),
  );
  const work = await client.query<{ readonly id: string; readonly operationId: string }>(
    `insert into control.configuration_work
       (participant_id,privacy_domain_id,operation_id,work_kind,resource_id,input_digest,
        configuration_digest,runtime_configuration_generation_id,runtime_target_id,
        generation_digest,predecessor_digest,policy_generation_digest,xds_version_digest)
     values($1,$2,uuidv7(),'RUNTIME_ACTIVATION',$3,$4,$5,$6,$3,$4,$7,$8,$9)
     returning configuration_work_id::text as id,operation_id::text as "operationId"`,
    [
      scope.participantId,
      scope.privacyDomainId,
      targetId,
      generationDigest,
      candidate.configurationDigest,
      generationId,
      expectedPredecessorDigest,
      policyGenerationDigest,
      xdsDigest,
    ],
  );
  const workRow = work.rows[0];
  if (workRow === undefined) throw new ContractError('PC-POLICY-2005');
  const now = timestamp(new Date());
  const workerOperation = {
    operationId: workRow.operationId,
    resourceRef: urn(targetId),
    actionIntentId: scope.actionIntentId,
    intentDigest: scope.actionIntentDigest as string,
    idempotencyKey: workRow.operationId,
    state: 'ACCEPTED',
    truthState: 'SUCCESS',
    createdAt: now,
    updatedAt: now,
    revision: expectedTargetRevision,
  };
  await client.query(
    `insert into control.idempotency_record
       (participant_id,principal_id,action_intent_id,catalog_operation_id,idempotency_key,
        operation_id,input_digest,expected_aggregate_version,result_aggregate_version,
        result_digest,result_payload,terminal_state,expires_at,privacy_domain_id)
     values($1,$2,$3,'LEGACY',$4,$5,$6,$7,$7,$8,$9,'COMMITTED',
            clock_timestamp()+interval '24 hours',$10)`,
    [
      scope.participantId,
      scope.principalId,
      scope.actionIntentId,
      workRow.operationId,
      workRow.operationId,
      bytes(generationDigest),
      expectedTargetRevision,
      digest(workerOperation),
      workerOperation,
      scope.privacyDomainId,
    ],
  );
  const target = await client.query(
    `update control.runtime_target
        set desired_generation_digest=$5,state='STAGING',policy_generation_digest=$6,
            observed_at=clock_timestamp(),revision=revision+1,updated_at=clock_timestamp()
      where participant_id=$1 and privacy_domain_id=$2 and runtime_target_id=$3 and revision=$4
        and active_generation_digest is not distinct from $7
        and state not in ('OFFLINE','QUARANTINED','INCOMPATIBLE')`,
    [
      scope.participantId,
      scope.privacyDomainId,
      targetId,
      expectedTargetRevision,
      generationDigest,
      policyGenerationDigest,
      expectedPredecessorDigest,
    ],
  );
  if (target.rowCount !== 1) throw new ContractError('PC-POLICY-2003');
  const linked = await client.query(
    `update control.policy_activation_occurrence_target
        set runtime_configuration_generation_id=$5,configuration_work_id=$6,
            command_operation_id=$7,state='STAGING',updated_at=clock_timestamp()
      where participant_id=$1 and privacy_domain_id=$2 and activation_occurrence_id=$3
        and runtime_target_id=$4 and phase=$8 and state in ('REQUESTED','ACTIVE_MATCHED')`,
    [
      scope.participantId,
      scope.privacyDomainId,
      occurrence.activationOccurrenceId,
      targetId,
      generationId,
      workRow.id,
      scope.operationId,
      phase,
    ],
  );
  if (linked.rowCount !== 1) throw new ContractError('PC-POLICY-2003');
}

export async function preparePolicyActivation(
  client: PoolClient,
  scope: ActivationScope,
  occurrence: OccurrenceRow,
  release: ReleaseCandidate,
  proof: StepUpProof,
): Promise<void> {
  const conflict = await client.query<{ readonly prior: Buffer | null }>(
    `select generation_digest as prior from control.policy_generation
        where participant_id=$1 and privacy_domain_id=$2 and scope_digest=$3
          and active=true and state='ACTIVE' and policy_generation_id<>$4 limit 2 for update`,
    [
      scope.participantId,
      scope.privacyDomainId,
      releaseScopeDigest(scope, release),
      occurrence.policyGenerationId,
    ],
  );
  process.stderr.write(
    JSON.stringify({
      boundary: 'policy_activation_preparation',
      stage: 'conflict_checked',
      occurrenceId: occurrence.activationOccurrenceId,
    }) + '\n',
  );
  if ((conflict.rowCount ?? 0) > 1) throw new ContractError('PC-POLICY-2003');
  const readyTargets = await exactTargets(client, scope);
  process.stderr.write(
    JSON.stringify({
      boundary: 'policy_activation_preparation',
      stage: 'targets_checked',
      occurrenceId: occurrence.activationOccurrenceId,
      count: readyTargets.length,
    }) + '\n',
  );
  if (
    readyTargets.length !== Number(occurrence.totalTargetCount) ||
    !cohortDigest(readyTargets).equals(occurrence.exactCohortDigest)
  ) {
    throw new ContractError('PC-POLICY-2003');
  }
  // A fully failed prior occurrence has no live effect. Fence its prepared
  // activation before taking the generation's unique pending slot again.
  await client.query(
    `update control.policy_activation activation
        set state='FAILED_FENCED',fenced_at=clock_timestamp(),row_version=row_version+1
      where activation.participant_id=$1 and activation.privacy_domain_id=$2
        and activation.policy_generation_id=$3 and activation.state='PREPARED'
        and activation.activated_at is null
        and exists (
          select 1 from control.policy_activation_occurrence prior
           where prior.activation_occurrence_id=activation.policy_activation_id
             and prior.policy_generation_id=$3 and prior.state='FAILED'
        )
        and exists (
          select 1 from control.policy_activation_occurrence_target target
           where target.activation_occurrence_id=activation.policy_activation_id
             and target.phase='FORWARD'
        )
        and not exists (
          select 1 from control.policy_activation_occurrence_target target
           join control.configuration_work work
             on work.configuration_work_id=target.configuration_work_id
           where target.activation_occurrence_id=activation.policy_activation_id
             and target.phase='FORWARD'
             and (target.state<>'FAILED' or work.state<>'FAILED')
        )`,
    [scope.participantId, scope.privacyDomainId, occurrence.policyGenerationId],
  );
  process.stderr.write(
    JSON.stringify({
      boundary: 'policy_activation_preparation',
      stage: 'prior_fenced',
      occurrenceId: occurrence.activationOccurrenceId,
    }) + '\n',
  );
  const activation = await client.query(
    `insert into control.policy_activation
         (policy_activation_id,participant_id,privacy_domain_id,policy_generation_id,
          approval_request_id,mfa_challenge_id,exact_cohort_digest,
          webauthn_assertion_binding_digest,prior_generation_digest,state)
       values($1,$2,$3,$4,$5,$6,$7,$8,$9,'PREPARED')`,
    [
      occurrence.activationOccurrenceId,
      scope.participantId,
      scope.privacyDomainId,
      occurrence.policyGenerationId,
      release.approvalRequestId,
      proof.mfaChallengeId,
      occurrence.exactCohortDigest,
      proof.assertionBindingDigest,
      conflict.rows[0]?.prior ?? null,
    ],
  );
  process.stderr.write(
    JSON.stringify({
      boundary: 'policy_activation_preparation',
      stage: 'activation_inserted',
      occurrenceId: occurrence.activationOccurrenceId,
      count: activation.rowCount,
    }) + '\n',
  );
  if (activation.rowCount !== 1) throw new ContractError('PC-POLICY-2005');
  const factReadinessReceipt = digest({
    authority: 'policy-simulation',
    simulationId: urn(release.simulationId),
    factGenerationDigest: digestString(release.factGenerationDigest),
    simulationResultDigest: digestString(release.simulationResultDigest),
    completedAt: timestamp(release.simulationCompletedAt),
  });
  const conflictClosureReceipt = digest({
    scopeDigest: digestString(releaseScopeDigest(scope, release)),
    targetGenerationDigest: digestString(occurrence.targetGenerationDigest),
    priorGenerationDigest:
      conflict.rows[0]?.prior === undefined || conflict.rows[0]?.prior === null
        ? null
        : digestString(conflict.rows[0].prior),
  });
  const prerequisites = [
    ['SIMULATION', occurrence.targetGenerationDigest, release.simulationResultDigest],
    ['APPROVAL', occurrence.targetGenerationDigest, release.approvalDecisionDigest],
    ['FACT_READINESS', release.factGenerationDigest, factReadinessReceipt],
    ['FLEET_READY', occurrence.exactCohortDigest, fleetReadinessReceipt(readyTargets)],
    ['DEPENDENCY_CLOSURE', release.dependencyClosureDigest, release.artifactPayloadDigest],
    ['CONFLICT_CLOSURE', occurrence.targetGenerationDigest, conflictClosureReceipt],
  ] as const;
  for (const [type, subject, receipt] of prerequisites) {
    await client.query(
      `insert into control.policy_activation_prerequisite
           (policy_activation_id,participant_id,privacy_domain_id,prerequisite_type,
            prerequisite_subject_digest,receipt_digest,ready,observed_at)
         values($1,$2,$3,$4,$5,$6,true,clock_timestamp())`,
      [
        occurrence.activationOccurrenceId,
        scope.participantId,
        scope.privacyDomainId,
        type,
        subject,
        digest({
          activationOccurrenceId: urn(occurrence.activationOccurrenceId),
          prerequisiteType: type,
          prerequisiteSubjectDigest: digestString(subject),
          authorityReceiptDigest: digestString(receipt),
        }),
      ],
    );
  }
}

/** Called only inside the ordinary CIGL candidate/approval/step-up transaction.
 * The policy owner retains release, simulation, exact cohort and prerequisite
 * ownership; the caller dispatches the reviewed profile selection atomically. */
export async function prepareProfiledPolicyRenewal(
  client: PoolClient,
  context: MutationContext,
  operationId: string,
  renewal: {
    activationOccurrenceRef: string;
    expectedRevision: string;
    policyGenerationDigest: string;
  },
): Promise<void> {
  const scope: ActivationScope = {
    ...context.authorization,
    operationId,
    actionIntentId: context.actionIntentId,
    actionIntentDigest: context.actionIntentDigest,
    idempotencyKey: context.idempotencyKey,
  };
  if (scope.actionIntentId !== 'ACT-CIGL_PROFILES_ACTIVATE_RESOURCE-V1')
    throw new ContractError('PC-POLICY-2004');
  const id = renewal.activationOccurrenceRef.slice('urn:openpc:resource:'.length);
  const occurrence = await occurrenceRow(client, scope, id, true);
  if (
    occurrence.state !== 'REQUESTED' ||
    occurrence.revision !== renewal.expectedRevision ||
    digestString(occurrence.targetGenerationDigest) !== renewal.policyGenerationDigest ||
    occurrence.totalTargetCount !== '1'
  )
    throw new ContractError('PC-POLICY-2003');
  const release = await releaseCandidate(
    client,
    scope,
    occurrence.releaseBundleId,
    occurrence.targetGenerationDigest,
  );
  // The published policy retains its original independent approval; the exact
  // renewal has a separate current maker/checker decision verified by the
  // CIGL mutation owner. Historical approval is never rewritten or consumed twice.
  if (
    !context.authorization.checkerPrincipalId ||
    context.authorization.checkerPrincipalId === scope.principalId
  )
    throw new ContractError('PC-POLICY-2004');
  const target = await client.query(
    `select 1 from control.policy_activation_occurrence_target cohort
    join control.runtime_target target on target.runtime_target_id=cohort.runtime_target_id
      and target.participant_id=cohort.participant_id and target.privacy_domain_id=cohort.privacy_domain_id
    where cohort.activation_occurrence_id=$1 and cohort.participant_id=$2 and cohort.privacy_domain_id=$3
      and cohort.runtime_target_id=$4 and cohort.phase='FORWARD' and cohort.state='REQUESTED'
      and cohort.configuration_work_id is null and cohort.expected_target_revision=target.revision
      and cohort.expected_predecessor_digest=target.active_generation_digest
      and target.state='ACTIVE_MATCHED' and target.active_generation_digest=target.desired_generation_digest`,
    [id, scope.participantId, scope.privacyDomainId, context.resourceId],
  );
  if (target.rowCount !== 1) throw new ContractError('PC-POLICY-2003');
  const proof = await stepUpProof(client, scope, context.authorization, digest(context.candidate));
  await preparePolicyActivation(client, scope, occurrence, release, proof);
  await recordControlEvent(
    client,
    scope,
    id,
    'openpc.policy.activation-occurrence.staging.v1',
    proof,
  );
}

export async function linkProfiledPolicyRenewal(
  client: PoolClient,
  context: MutationContext,
  operationId: string,
  renewal: {
    activationOccurrenceRef: string;
    expectedRevision: string;
    policyGenerationDigest: string;
  },
): Promise<void> {
  const id = renewal.activationOccurrenceRef.slice('urn:openpc:resource:'.length);
  const linked = await client.query(
    `update control.policy_activation_occurrence_target cohort
    set runtime_configuration_generation_id=work.runtime_configuration_generation_id,
      configuration_work_id=work.configuration_work_id,command_operation_id=work.operation_id,
      state='STAGING',updated_at=clock_timestamp()
    from control.configuration_work work where cohort.activation_occurrence_id=$1
      and cohort.participant_id=$2 and cohort.privacy_domain_id=$3 and cohort.runtime_target_id=$4
      and cohort.phase='FORWARD' and cohort.state='REQUESTED' and cohort.configuration_work_id is null
      and work.operation_id=$5 and work.participant_id=cohort.participant_id
      and work.privacy_domain_id=cohort.privacy_domain_id and work.runtime_target_id=cohort.runtime_target_id
      and work.work_kind='RUNTIME_ACTIVATION' and work.policy_generation_digest=$6`,
    [
      id,
      context.authorization.participantId,
      context.authorization.privacyDomainId,
      context.resourceId,
      operationId,
      renewal.policyGenerationDigest,
    ],
  );
  if (linked.rowCount !== 1) throw new ContractError('PC-POLICY-2003');
  const changed = await client.query(
    `update control.policy_activation_occurrence
    set state='STAGING',matched_target_count=0,revision=revision+1,updated_at=clock_timestamp()
    where activation_occurrence_id=$1 and participant_id=$2 and privacy_domain_id=$3
      and state='REQUESTED' and revision=$4`,
    [
      id,
      context.authorization.participantId,
      context.authorization.privacyDomainId,
      renewal.expectedRevision,
    ],
  );
  if (changed.rowCount !== 1) throw new ContractError('PC-POLICY-2003');
}

export async function activatePublicOccurrence(
  pool: Pool,
  scope: PublicApprovalScope,
  authority: CommandAuthority,
  id: string,
  expectedRevision: string,
  inputDigestText: string,
): Promise<PublicOperation> {
  let stage = 'scope';
  return inScope(pool, scope, async (client) => {
    stage = 'intent';
    const intent = await assertActionIntent(client, scope, 'ACTIVATE', [
      'release',
      'activation-occurrence',
    ]);
    const inputDigest = bytes(inputDigestText);
    stage = 'operation_reservation';
    const replay = await reserveOperation(client, scope, inputDigest, expectedRevision);
    if (replay !== undefined) return replay;
    const occurrence = await occurrenceRow(client, scope, id, true);
    stage = 'occurrence_validation';
    if (
      occurrence.state !== 'REQUESTED' ||
      occurrence.revision !== expectedRevision ||
      !expectedCommandDigest(scope.actionIntentId, id, occurrence, expectedRevision).equals(
        inputDigest,
      )
    ) {
      throw new ContractError('PC-POLICY-2003');
    }
    const release = await releaseCandidate(
      client,
      scope,
      occurrence.releaseBundleId,
      occurrence.targetGenerationDigest,
    );
    stage = 'release_validation';
    if (
      release.checkerPrincipalId !== scope.principalId ||
      release.createdByPrincipalId === scope.principalId
    )
      throw new ContractError('PC-POLICY-2004');
    // A historical publication does not carry its approval across expiry,
    // revocation or a root transition. Renewal has its own fresh governed owner.
    stage = 'current_release_approval';
    const approval = await approvalAuthorityDependencies(
      client,
      scope,
      release.approvalRequestId,
      true,
    );
    await fenceBoundAuthorities(client, scope.participantId, approval.authorities, approval.rows);
    await approvalAuthorityDependencies(client, scope, release.approvalRequestId, true);
    stage = 'step_up_proof';
    const proof = await stepUpProof(client, scope, authority, inputDigest);
    stage = 'activation_preparation';
    await preparePolicyActivation(client, scope, occurrence, release, proof);
    stage = 'target_dispatch';
    const targets = await client.query<{
      readonly targetId: string;
      readonly expectedTargetRevision: string;
      readonly expectedPredecessorDigest: string | null;
    }>(
      `select runtime_target_id::text as "targetId",
              expected_target_revision::text as "expectedTargetRevision",
              expected_predecessor_digest as "expectedPredecessorDigest"
         from control.policy_activation_occurrence_target
        where participant_id=$1 and privacy_domain_id=$2 and activation_occurrence_id=$3
          and phase='FORWARD' order by runtime_target_id for update`,
      [scope.participantId, scope.privacyDomainId, id],
    );
    if (targets.rowCount !== Number(occurrence.totalTargetCount))
      throw new ContractError('PC-POLICY-2003');
    for (const target of targets.rows) {
      await dispatchTarget(
        client,
        scope,
        occurrence,
        target.targetId,
        target.expectedTargetRevision,
        target.expectedPredecessorDigest,
        'FORWARD',
        digestString(occurrence.targetGenerationDigest),
      );
    }
    const changed = await client.query<{ readonly revision: string }>(
      `update control.policy_activation_occurrence
          set state='STAGING',matched_target_count=0,revision=revision+1,
              updated_at=clock_timestamp()
        where participant_id=$1 and privacy_domain_id=$2 and activation_occurrence_id=$3
          and state='REQUESTED' and revision=$4 returning revision::text as revision`,
      [scope.participantId, scope.privacyDomainId, id, expectedRevision],
    );
    stage = 'occurrence_transition';
    const row = changed.rows[0];
    if (row === undefined) throw new ContractError('PC-POLICY-2002');
    const used = await client.query(
      `update control.mfa_challenge set used_at=clock_timestamp(),used_operation_id=$2,
              row_version=row_version+1
        where mfa_challenge_id=$1 and used_at is null`,
      [proof.mfaChallengeId, scope.operationId],
    );
    if (used.rowCount !== 1) throw new ContractError('PC-POLICY-2004');
    await recordControlEvent(
      client,
      scope,
      id,
      'openpc.policy.activation-occurrence.staging.v1',
      proof,
    );
    stage = 'operation_completion';
    return completeOperation(client, scope, intent, id, row.revision);
  }).catch((error: unknown) => {
    const value = error as { readonly code?: unknown };
    process.stderr.write(
      JSON.stringify({
        boundary: 'policy_activation',
        stage,
        occurrenceId: id,
        errorCode:
          typeof value.code === 'string' && /^(?:[0-9A-Z]{5}|PC-POLICY-[0-9]{4})$/u.test(value.code)
            ? value.code
            : 'unknown',
        disposition: 'READBACK_OR_DIAGNOSE_BEFORE_RETRY',
      }) + '\n',
    );
    throw error;
  });
}

export async function recoverPublicOccurrence(
  pool: Pool,
  scope: PublicApprovalScope,
  authority: CommandAuthority,
  id: string,
  expectedRevision: string,
  inputDigestText: string,
): Promise<PublicOperation> {
  return inScope(pool, scope, async (client) => {
    const intent = await assertActionIntent(client, scope, 'RECOVER', ['activation-occurrence']);
    const inputDigest = bytes(inputDigestText);
    const replay = await reserveOperation(client, scope, inputDigest, expectedRevision);
    if (replay !== undefined) return replay;
    const occurrence = await occurrenceRow(client, scope, id, true);
    // Older failure aggregation could retain STAGING after its entire durable
    // cohort had stopped. Recover only the proven failed cohort, never live work.
    const retainedFailure =
      occurrence.state === 'STAGING'
        ? await client.query<{ readonly recoverable: boolean }>(
            `select count(*)>0
              and bool_and(target.state in ('FAILED','WRITE_AMBIGUITY','ACTIVE_MATCHED'))
              and bool_or(target.state in ('FAILED','WRITE_AMBIGUITY')) as recoverable
             from control.policy_activation_occurrence_target target
            where target.participant_id=$1 and target.privacy_domain_id=$2
              and target.activation_occurrence_id=$3 and target.phase='FORWARD'`,
            [scope.participantId, scope.privacyDomainId, id],
          )
        : undefined;
    if (
      (!['PARTIAL', 'FAILED'].includes(occurrence.state) &&
        retainedFailure?.rows[0]?.recoverable !== true) ||
      occurrence.revision !== expectedRevision ||
      !expectedCommandDigest(scope.actionIntentId, id, occurrence, expectedRevision).equals(
        inputDigest,
      )
    ) {
      throw new ContractError('PC-POLICY-2003');
    }
    const proof = await stepUpProof(client, scope, authority, inputDigest);
    const failed = await client.query<{
      readonly workId: string;
      readonly targetId: string;
      readonly phase: 'FORWARD' | 'ROLLBACK';
    }>(
      `select target.configuration_work_id::text as "workId",
              target.runtime_target_id::text as "targetId",target.phase
         from control.policy_activation_occurrence_target target
        where target.participant_id=$1 and target.privacy_domain_id=$2
          and target.activation_occurrence_id=$3
          and target.phase=case when exists (
            select 1 from control.policy_activation_occurrence_target rollback
             where rollback.participant_id=$1 and rollback.privacy_domain_id=$2
               and rollback.activation_occurrence_id=$3 and rollback.phase='ROLLBACK'
          ) then 'ROLLBACK' else 'FORWARD' end
          and target.state in ('FAILED','WRITE_AMBIGUITY') for update`,
      [scope.participantId, scope.privacyDomainId, id],
    );
    if (failed.rowCount === 0) throw new ContractError('PC-POLICY-2003');
    for (const target of failed.rows) {
      const work = await client.query<{ readonly state: string }>(
        `select state from control.configuration_work
          where participant_id=$1 and privacy_domain_id=$2 and configuration_work_id=$3 for update`,
        [scope.participantId, scope.privacyDomainId, target.workId],
      );
      const state = work.rows[0]?.state;
      if (state === 'FAILED') {
        await client.query(
          `update control.configuration_work
              set state='PENDING',attempt_count=0,lease_owner=null,lease_until=null,
                  execution_attempt_id=null,execution_started_at=null,reconcile_after=null,
                  result_receipt=null,result_receipt_digest=null,result_event_id=null,
                  last_error_code=null,completed_at=null,updated_at=clock_timestamp()
            where participant_id=$1 and privacy_domain_id=$2 and configuration_work_id=$3
              and state='FAILED'`,
          [scope.participantId, scope.privacyDomainId, target.workId],
        );
        await client.query(
          `update control.runtime_configuration_generation set state='ACTIVATING',revision=revision+1
            where participant_id=$1 and privacy_domain_id=$2
              and runtime_configuration_generation_id=(select runtime_configuration_generation_id
                from control.configuration_work where configuration_work_id=$3) and state='FAILED'`,
          [scope.participantId, scope.privacyDomainId, target.workId],
        );
        await client.query(
          `update control.runtime_target set state='STAGING',revision=revision+1,
                  updated_at=clock_timestamp()
            where participant_id=$1 and privacy_domain_id=$2 and runtime_target_id=$3
              and state='FAILED'`,
          [scope.participantId, scope.privacyDomainId, target.targetId],
        );
      } else if (state === 'RECONCILING') {
        await client.query(
          `update control.configuration_work set reconcile_after=clock_timestamp(),
                  updated_at=clock_timestamp()
            where participant_id=$1 and privacy_domain_id=$2 and configuration_work_id=$3
              and state='RECONCILING'`,
          [scope.participantId, scope.privacyDomainId, target.workId],
        );
      } else {
        throw new ContractError('PC-POLICY-2003');
      }
      await client.query(
        `update control.policy_activation_occurrence_target
            set state='STAGING',command_operation_id=$4,updated_at=clock_timestamp()
          where participant_id=$1 and privacy_domain_id=$2 and configuration_work_id=$3
            and state in ('FAILED','WRITE_AMBIGUITY')`,
        [scope.participantId, scope.privacyDomainId, target.workId, scope.operationId],
      );
    }
    const changed = await client.query<{ readonly revision: string }>(
      `update control.policy_activation_occurrence
          set state=case when $5='ROLLBACK' then 'ROLLING_BACK'
                         when matched_target_count>0 then 'PARTIAL' else 'STAGING' end,
              revision=revision+1,updated_at=clock_timestamp()
        where participant_id=$1 and privacy_domain_id=$2 and activation_occurrence_id=$3
          and revision=$4 returning revision::text as revision`,
      [scope.participantId, scope.privacyDomainId, id, expectedRevision, failed.rows[0]!.phase],
    );
    const row = changed.rows[0];
    if (row === undefined) throw new ContractError('PC-POLICY-2002');
    const used = await client.query(
      `update control.mfa_challenge set used_at=clock_timestamp(),used_operation_id=$2,
              row_version=row_version+1 where mfa_challenge_id=$1 and used_at is null`,
      [proof.mfaChallengeId, scope.operationId],
    );
    if (used.rowCount !== 1) throw new ContractError('PC-POLICY-2004');
    await recordControlEvent(
      client,
      scope,
      id,
      'openpc.policy.activation-occurrence.recovery-requested.v1',
      proof,
    );
    return completeOperation(client, scope, intent, id, row.revision);
  });
}

export async function rollbackPublicOccurrence(
  pool: Pool,
  scope: PublicApprovalScope,
  authority: CommandAuthority,
  id: string,
  expectedRevision: string,
  inputDigestText: string,
): Promise<PublicOperation> {
  return inScope(pool, scope, async (client) => {
    const intent = await assertActionIntent(client, scope, 'ROLLBACK', [
      'release',
      'activation-occurrence',
    ]);
    const inputDigest = bytes(inputDigestText);
    const replay = await reserveOperation(client, scope, inputDigest, expectedRevision);
    if (replay !== undefined) return replay;
    const occurrence = await occurrenceRow(client, scope, id, true);
    if (
      occurrence.state !== 'ACTIVE_MATCHED' ||
      occurrence.revision !== expectedRevision ||
      !expectedCommandDigest(scope.actionIntentId, id, occurrence, expectedRevision).equals(
        inputDigest,
      )
    ) {
      throw new ContractError('PC-POLICY-2003');
    }
    const proof = await stepUpProof(client, scope, authority, inputDigest);
    const prior = await client.query<{ readonly generationDigest: Buffer }>(
      `select prior.generation_digest as "generationDigest"
         from control.policy_activation activation
         join control.policy_generation current_generation
           on current_generation.participant_id=activation.participant_id
          and current_generation.privacy_domain_id=activation.privacy_domain_id
          and current_generation.policy_generation_id=activation.policy_generation_id
         join control.policy_generation prior
           on prior.participant_id=activation.participant_id
          and prior.privacy_domain_id=activation.privacy_domain_id
          and prior.scope_digest=current_generation.scope_digest
          and prior.generation_digest=activation.prior_generation_digest
        where activation.participant_id=$1 and activation.privacy_domain_id=$2
          and activation.policy_activation_id=$3 and activation.state='ACTIVE'
          and prior.state='RETIRED' and prior.active=false limit 2 for update of activation,prior`,
      [scope.participantId, scope.privacyDomainId, id],
    );
    const priorGeneration = prior.rows[0];
    if (prior.rowCount !== 1 || priorGeneration === undefined)
      throw new ContractError('PC-POLICY-2003');
    const targets = await client.query<{
      readonly targetId: string;
      readonly revision: string;
      readonly predecessor: string;
    }>(
      `select runtime.runtime_target_id::text as "targetId",runtime.revision::text as revision,
              runtime.active_generation_digest as predecessor
         from control.policy_activation_occurrence_target cohort
         join control.runtime_target runtime
           on runtime.participant_id=cohort.participant_id
          and runtime.privacy_domain_id=cohort.privacy_domain_id
          and runtime.runtime_target_id=cohort.runtime_target_id
        where cohort.participant_id=$1 and cohort.privacy_domain_id=$2
          and cohort.activation_occurrence_id=$3 and cohort.phase='FORWARD'
          and cohort.state='ACTIVE_MATCHED' and cohort.activation_receipt_digest is not null
          and runtime.state='ACTIVE_MATCHED' and runtime.active_generation_digest is not null
        order by runtime.runtime_target_id for update of runtime`,
      [scope.participantId, scope.privacyDomainId, id],
    );
    if (targets.rowCount !== Number(occurrence.totalTargetCount))
      throw new ContractError('PC-POLICY-2003');
    for (const target of targets.rows) {
      await client.query(
        `insert into control.policy_activation_occurrence_target
           (activation_occurrence_id,participant_id,privacy_domain_id,runtime_target_id,phase,
            expected_target_revision,expected_predecessor_digest,state,command_operation_id)
         values($1,$2,$3,$4,'ROLLBACK',$5,$6,'REQUESTED',$7)`,
        [
          id,
          scope.participantId,
          scope.privacyDomainId,
          target.targetId,
          target.revision,
          target.predecessor,
          scope.operationId,
        ],
      );
      await dispatchTarget(
        client,
        scope,
        occurrence,
        target.targetId,
        target.revision,
        target.predecessor,
        'ROLLBACK',
        digestString(priorGeneration.generationDigest),
      );
    }
    const changed = await client.query<{ readonly revision: string }>(
      `update control.policy_activation_occurrence
          set state='ROLLING_BACK',matched_target_count=0,rollback_started_at=clock_timestamp(),
              revision=revision+1,updated_at=clock_timestamp()
        where participant_id=$1 and privacy_domain_id=$2 and activation_occurrence_id=$3
          and state='ACTIVE_MATCHED' and revision=$4 returning revision::text as revision`,
      [scope.participantId, scope.privacyDomainId, id, expectedRevision],
    );
    const row = changed.rows[0];
    if (row === undefined) throw new ContractError('PC-POLICY-2002');
    const used = await client.query(
      `update control.mfa_challenge set used_at=clock_timestamp(),used_operation_id=$2,
              row_version=row_version+1 where mfa_challenge_id=$1 and used_at is null`,
      [proof.mfaChallengeId, scope.operationId],
    );
    if (used.rowCount !== 1) throw new ContractError('PC-POLICY-2004');
    await recordControlEvent(
      client,
      scope,
      id,
      'openpc.policy.activation-occurrence.rollback-requested.v1',
      proof,
    );
    return completeOperation(client, scope, intent, id, row.revision);
  });
}
