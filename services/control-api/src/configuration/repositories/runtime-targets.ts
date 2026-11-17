import { ContractError } from '../../../../module-registry/src/domain/errors.js';
import {
  prepareProfiledPolicyRenewal,
  linkProfiledPolicyRenewal,
} from '../../../../module-registry/src/db/public-activation-store.js';
import type { Pool } from 'pg';
import type { IdentityRuntimeVerifier } from '../../../../identity-service/src/domain/identity-runtime-crypto.js';

import { type ListRequest, type PageResult, selectPage } from '../pagination.js';
import { sha256 } from '../digest.js';
import type { ActivateCiglProfiles } from '../cigl/activation-contract.js';
import { fenceCiglActivationSources } from '../cigl/activation-sources.js';
import { AtomicConfigurationMutation } from '../persistence/atomic-mutation.js';
import { ScopedConfigurationRead, type ReadContext } from '../persistence/scoped-read.js';
import {
  ConfigurationRepositoryError,
  type MutationContext,
  type OperationRecord,
} from '../persistence/types.js';

export interface RuntimeTargetRecord {
  readonly targetId: string;
  readonly participantId: string;
  readonly desiredGenerationDigest: string | null;
  readonly activeGenerationDigest: string | null;
  readonly xdsVersionDigest: string | null;
  readonly state: string;
  readonly observedAt: string;
  readonly revision: string;
  readonly createdAt: string;
  readonly updatedAt: string;
}

const targetProjection = `runtime_target_id as "targetId",participant_id as "participantId",
  desired_generation_digest as "desiredGenerationDigest",active_generation_digest as "activeGenerationDigest",
  xds_version_digest as "xdsVersionDigest",state,observed_at::text as "observedAt",revision::text,
  created_at::text as "createdAt",updated_at::text as "updatedAt"`;

const targetRecord = (row: RuntimeTargetRecord): RuntimeTargetRecord => ({
  ...row,
  targetId: `urn:openpc:resource:${row.targetId}`,
  participantId: `urn:openpc:participant:${row.participantId}`,
  observedAt: new Date(row.observedAt).toISOString().replace(/\.([0-9]{3})Z$/u, '.$1000Z'),
  createdAt: new Date(row.createdAt).toISOString().replace(/\.([0-9]{3})Z$/u, '.$1000Z'),
  updatedAt: new Date(row.updatedAt).toISOString().replace(/\.([0-9]{3})Z$/u, '.$1000Z'),
});

function policyRenewalError(error: unknown): never {
  if (error instanceof ContractError) {
    throw new ConfigurationRepositoryError(
      error.code === 'PC-POLICY-2004' ? 'PC-AUTH-0005' : 'PC-DATA-6007',
    );
  }
  throw error;
}

/** Shared derivation for readback and the guarded activation mutation. */
const runtimeActivationCandidateSql = (
  targetParameter: '$1' | '$2',
) => `select 'sha256:'||encode(sha256(
             configuration.configuration_digest||policy.generation_digest||
             convert_to(provider.behavior_fingerprint,'UTF8')||
             convert_to(projection.plan_digest,'UTF8')||
             convert_to(target.runtime_target_id::text,'UTF8')),'hex') generation_digest,
             'sha256:'||encode(policy.generation_digest,'hex') policy_generation_digest,
             'sha256:'||encode(configuration.configuration_digest,'hex') configuration_digest,
             provider.provider_profile_id,projection.projection_plan_id,
             openpc.runtime_installed_predecessor(target.runtime_target_id) predecessor_digest,
             (select configuration_work_id from openpc.runtime_denied_predecessor(target.runtime_target_id)) denied_predecessor_work_id,
             target.participant_id,target.privacy_domain_id,target.runtime_target_id
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
             join control.policy_generation policy on policy.participant_id=target.participant_id
              and policy.privacy_domain_id=target.privacy_domain_id
              and policy.state='ACTIVE' and policy.active=true
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
            where target.runtime_target_id=${targetParameter}
             and target.state not in ('QUARANTINED','INCOMPATIBLE')
             and not exists(select 1 from control.configuration_work pending where pending.participant_id=target.participant_id and pending.privacy_domain_id=target.privacy_domain_id and pending.runtime_target_id=target.runtime_target_id and pending.work_kind='RUNTIME_ACTIVATION' and pending.state in ('PENDING','LEASED','RECONCILING'))
             and openpc.runtime_target_discovery_current(target.participant_id,target.privacy_domain_id,target.runtime_target_id)
             and not exists (
               select 1 from control.runtime_activation_observation observed
               join control.runtime_configuration_generation prior
                 on prior.runtime_configuration_generation_id=observed.runtime_configuration_generation_id
               where observed.runtime_target_id=target.runtime_target_id
                 and observed.capsule_digest=target.active_generation_digest
                 and prior.cigl_profile_selection is not null)`;

export class RuntimeTargetRepository {
  private readonly mutations: AtomicConfigurationMutation;
  private readonly reads: ScopedConfigurationRead;

  constructor(
    private readonly pool: Pool,
    identityRuntimeVerifier?: IdentityRuntimeVerifier,
  ) {
    this.mutations = new AtomicConfigurationMutation(pool, identityRuntimeVerifier);
    this.reads = new ScopedConfigurationRead(pool);
  }

  async create(
    context: MutationContext,
    _input: {
      readonly desiredGenerationDigest: string | null;
      readonly activeGenerationDigest: string | null;
      readonly xdsVersionDigest: string | null;
      readonly observedAt: string;
    },
  ): Promise<OperationRecord> {
    return this.mutations.execute(context, async (client, targetId) => {
      const inserted = await client.query<RuntimeTargetRecord>(
        `insert into control.runtime_target
         (runtime_target_id,participant_id,privacy_domain_id,desired_generation_digest,
           active_generation_digest,xds_version_digest,observed_at,policy_generation_digest,requires_authenticated_discovery)
         select $1,$2,$3,null,null,null,clock_timestamp(),provenance.digest,true
           from (select openpc.configuration_policy_provenance($2::uuid,$3::uuid) digest) provenance
         returning ${targetProjection}`,
        [targetId, context.authorization.participantId, context.authorization.privacyDomainId],
      );
      const result = inserted.rows[0]!;
      return { result, revision: result.revision, outboxEventType: 'runtime-target.discovered.v1' };
    });
  }

  async update(context: MutationContext, replacementDigest: string): Promise<OperationRecord> {
    return this.queueActivation(context, replacementDigest);
  }

  async activateCiglProfiles(
    context: MutationContext,
    input: ActivateCiglProfiles,
  ): Promise<OperationRecord> {
    return this.queueActivation(context, input.expectedGenerationDigest, input);
  }

  private async queueActivation(
    context: MutationContext,
    replacementDigest: string,
    cigl?: ActivateCiglProfiles,
  ): Promise<OperationRecord> {
    return this.mutations.execute(context, async (client, _resourceId, operationId) => {
      if (cigl !== undefined) {
        await fenceCiglActivationSources(client, context, cigl);
        if (cigl.policyRenewal !== undefined)
          await prepareProfiledPolicyRenewal(
            client,
            context,
            operationId,
            cigl.policyRenewal,
          ).catch(policyRenewalError);
      } else {
        // A generic resource change cannot silently remove installed profiles.
        // Their exact next selection requires the governed profile command.
        const profiled = await client.query(
          `select 1 from control.runtime_target target join control.runtime_activation_observation observation
           on observation.runtime_target_id=target.runtime_target_id and observation.capsule_digest=target.active_generation_digest
           join control.runtime_configuration_generation generation on generation.runtime_configuration_generation_id=observation.runtime_configuration_generation_id
           where target.runtime_target_id=$1 and generation.cigl_profile_selection is not null`,
          [context.resourceId],
        );
        if (profiled.rowCount !== 0) throw new ConfigurationRepositoryError('PC-DATA-6007');
      }
      const selection =
        cigl === undefined
          ? null
          : {
              participantEpoch: cigl.participantEpoch,
              profiles: cigl.profiles,
              ...(cigl.policyRenewal === undefined ? {} : { policyRenewal: cigl.policyRenewal }),
            };
      const xdsVersionDigest = sha256({
        // Renewing unchanged configuration still publishes fresh capsule
        // custody and must cross a new proxy acknowledgement barrier.
        operationId,
        generationDigest: replacementDigest,
        runtimeTargetId: context.resourceId,
      });
      const changed = await client.query<RuntimeTargetRecord>(
        `with candidate as (
           ${runtimeActivationCandidateSql('$2')} and $6::jsonb is null
           union all
           select target.active_generation_digest,coalesce($6::jsonb->'policyRenewal'->>'policyGenerationDigest',previous.policy_generation_digest),
             previous_work.configuration_digest,previous.provider_profile_id,previous.projection_plan_id,
             target.active_generation_digest,null::uuid,target.participant_id,target.privacy_domain_id,target.runtime_target_id
           from control.runtime_target target
           join control.runtime_activation_observation observation
             on observation.runtime_target_id=target.runtime_target_id
            and observation.participant_id=target.participant_id and observation.privacy_domain_id=target.privacy_domain_id
            and observation.capsule_digest=target.active_generation_digest
           join control.runtime_configuration_generation previous
             on previous.runtime_configuration_generation_id=observation.runtime_configuration_generation_id
            and previous.participant_id=target.participant_id and previous.privacy_domain_id=target.privacy_domain_id
            and previous.generation_digest=observation.generation_digest and previous.state='ACTIVE'
           join control.configuration_work previous_work
             on previous_work.configuration_work_id=observation.configuration_work_id
            and previous_work.runtime_configuration_generation_id=previous.runtime_configuration_generation_id
            and previous_work.participant_id=target.participant_id and previous_work.privacy_domain_id=target.privacy_domain_id
            and previous_work.generation_digest=previous.generation_digest and previous_work.state='COMPLETED'
           where target.runtime_target_id=$2 and $6::jsonb is not null
             and openpc.runtime_target_discovery_current(target.participant_id,target.privacy_domain_id,target.runtime_target_id)
             and target.state='ACTIVE_MATCHED' and target.active_generation_digest=target.desired_generation_digest
             and target.policy_generation_digest=previous.policy_generation_digest
         ), exact_candidate as (
           select min(generation_digest) generation_digest,
                  min(policy_generation_digest) policy_generation_digest,
                  min(configuration_digest) configuration_digest,
                  min(provider_profile_id::text)::uuid provider_profile_id,
                  min(projection_plan_id::text)::uuid projection_plan_id,
                  min(predecessor_digest) predecessor_digest,
                  min(denied_predecessor_work_id::text)::uuid denied_predecessor_work_id,
                  min(participant_id::text)::uuid participant_id,
                  min(privacy_domain_id::text)::uuid privacy_domain_id,
                  min(runtime_target_id::text)::uuid runtime_target_id
             from candidate having count(*)=1 and min(generation_digest)=$1
         ), generation as (
           insert into control.runtime_configuration_generation
             (participant_id,privacy_domain_id,runtime_target_id,provider_profile_id,
              projection_plan_id,predecessor_digest,generation_digest,policy_generation_digest,state,cigl_profile_selection)
           select participant_id,privacy_domain_id,runtime_target_id,provider_profile_id,
             projection_plan_id,predecessor_digest,
             case when $6::jsonb is null then generation_digest else 'sha256:'||encode(sha256(convert_to(
               openpc.signing_canonical_json(jsonb_build_object('purpose','openpc.runtime.cigl-profile-selection.v1',
                'baseCapsuleDigest',generation_digest,'selection',$6::jsonb)),'UTF8')),'hex') end,
             policy_generation_digest,'ACTIVATING',$6::jsonb
             from exact_candidate returning *
         ), target_update as (
           update control.runtime_target target set desired_generation_digest=generation.generation_digest,
             state='STAGING',policy_generation_digest=generation.policy_generation_digest,
             observed_at=clock_timestamp(),revision=target.revision+1,updated_at=clock_timestamp()
           from generation where target.runtime_target_id=generation.runtime_target_id
             and target.revision=$3 and target.state not in ('QUARANTINED','INCOMPATIBLE')
           returning target.*
         ), work as (
           insert into control.configuration_work
             (participant_id,privacy_domain_id,operation_id,work_kind,resource_id,input_digest,
              configuration_digest,
              runtime_configuration_generation_id,runtime_target_id,generation_digest,
              predecessor_digest,policy_generation_digest,xds_version_digest,denied_predecessor_work_id)
           select generation.participant_id,generation.privacy_domain_id,$4,'RUNTIME_ACTIVATION',
             generation.runtime_target_id,case when $6::jsonb is null then $1 else $7 end,exact_candidate.configuration_digest,
             generation.runtime_configuration_generation_id,
             generation.runtime_target_id,generation.generation_digest,generation.predecessor_digest,
             generation.policy_generation_digest,$5,exact_candidate.denied_predecessor_work_id from generation,target_update,exact_candidate
         )
         select ${targetProjection} from target_update`,
        [
          replacementDigest,
          context.resourceId,
          context.expectedRevision,
          operationId,
          xdsVersionDigest,
          selection === null ? null : JSON.stringify(selection),
          sha256(context.candidate),
        ],
      );
      if (changed.rowCount !== 1) throw new ConfigurationRepositoryError('PC-DATA-6007');
      if (cigl?.policyRenewal !== undefined)
        await linkProfiledPolicyRenewal(client, context, operationId, cigl.policyRenewal).catch(
          policyRenewalError,
        );
      const result = changed.rows[0]!;
      return {
        result,
        revision: result.revision,
        outboxEventType:
          cigl === undefined
            ? 'runtime-target.activation-requested.v1'
            : 'openpc.cigl.profile.activation-requested.v1',
        asynchronous: true,
      };
    });
  }

  async get(context: ReadContext): Promise<RuntimeTargetRecord> {
    return this.reads.execute(context, async (client) => {
      const selected = await client.query<RuntimeTargetRecord>(
        `select ${targetProjection} from control.runtime_target where runtime_target_id=$1`,
        [context.resourceId],
      );
      if (selected.rowCount !== 1) throw new ConfigurationRepositoryError('PC-FACT-4001');
      return targetRecord(selected.rows[0]!);
    });
  }

  async activationCandidate(context: ReadContext) {
    // Candidate sources are new custody uses: observe current disposition and
    // fence authority through commit rather than using a historical read view.
    return this.reads.executeCurrent(context, async (client) => {
      const selected = await client.query<{ revision: string }>(
        'select revision::text from control.runtime_target where runtime_target_id=$1',
        [context.resourceId],
      );
      if (selected.rowCount !== 1) throw new ConfigurationRepositoryError('PC-FACT-4001');
      const candidates = await client.query<{ generation_digest: string }>(
        runtimeActivationCandidateSql('$1'),
        [context.resourceId],
      );
      return {
        targetRef: `urn:openpc:resource:${context.resourceId}`,
        expectedRevision: selected.rows[0]!.revision,
        replacementDigest: candidates.rowCount === 1 ? candidates.rows[0]!.generation_digest : null,
      };
    });
  }

  async list(context: ReadContext, request: ListRequest): Promise<PageResult<RuntimeTargetRecord>> {
    return this.reads.execute(context, async (client) => {
      return selectPage(client, request, {
        table: 'control.runtime_target',
        idColumn: 'runtime_target_id',
        projection: targetProjection,
        filterColumns: { state: 'state' },
        rowId: (row: RuntimeTargetRecord) => row.targetId,
        rowUpdatedAt: (row: RuntimeTargetRecord) => row.updatedAt,
        map: targetRecord,
      });
    });
  }
}
