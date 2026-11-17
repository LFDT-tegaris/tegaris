import type { ConfigurationBusinessEvidence } from '../persistence/business-receipt-writer.js';
import { businessTransitionProfileForOperation } from '@openpc/security-kernel';
import type { Pool, PoolClient } from 'pg';
import type { IdentityRuntimeVerifier } from '../../../../identity-service/src/domain/identity-runtime-crypto.js';

import { type ListRequest, type PageResult, selectPage } from '../pagination.js';
import { AtomicConfigurationMutation } from '../persistence/atomic-mutation.js';
import {
  assertIndexerBusinessTransition,
  bindIndexerBusinessState,
  IndexerBusinessTransitionError,
  readIndexerBusinessState,
} from '../persistence/business-state/indexer.js';
import { ScopedConfigurationRead, type ReadContext } from '../persistence/scoped-read.js';
import {
  ConfigurationRepositoryError,
  type MutationContext,
  type OperationRecord,
} from '../persistence/types.js';

export interface IndexerProfileRecord {
  readonly indexerProfileId: string;
  readonly participantId: string;
  readonly engine: 'CLIENT_INDEXER' | 'EXTERNAL_ENGINE_ADAPTER';
  readonly engineVersion: string;
  readonly methodProfileDigest: string;
  readonly state: 'REGISTERED' | 'SHADOW' | 'QUALIFIED' | 'ACTIVE' | 'QUARANTINED' | 'RETIRED';
  readonly authority: 'CANDIDATE_ONLY';
  readonly revision: string;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface ProjectionPlanRecord {
  readonly projectionPlanId: string;
  readonly indexerProfileId: string;
  readonly planDigest: string;
  readonly state: 'DRAFT' | 'VALIDATED' | 'RUNNING' | 'DEGRADED' | 'QUARANTINED' | 'RETIRED';
  readonly readiness: 'UNKNOWN' | 'NOT_READY' | 'READY' | 'STALE' | 'REORG';
  readonly revision: string;
  readonly createdAt: string;
  readonly updatedAt: string;
}

type IndexerRow = Omit<IndexerProfileRecord, 'authority'>;
const indexerRecord = (row: IndexerRow): IndexerProfileRecord => ({
  ...row,
  indexerProfileId: `urn:openpc:resource:${row.indexerProfileId}`,
  participantId: `urn:openpc:participant:${row.participantId}`,
  createdAt: new Date(row.createdAt).toISOString().replace(/\.([0-9]{3})Z$/u, '.$1000Z'),
  updatedAt: new Date(row.updatedAt).toISOString().replace(/\.([0-9]{3})Z$/u, '.$1000Z'),
  authority: 'CANDIDATE_ONLY',
});

const projectionRecord = (row: ProjectionPlanRecord): ProjectionPlanRecord => ({
  ...row,
  projectionPlanId: `urn:openpc:resource:${row.projectionPlanId}`,
  indexerProfileId: `urn:openpc:resource:${row.indexerProfileId}`,
  createdAt: new Date(row.createdAt).toISOString().replace(/\.([0-9]{3})Z$/u, '.$1000Z'),
  updatedAt: new Date(row.updatedAt).toISOString().replace(/\.([0-9]{3})Z$/u, '.$1000Z'),
});

export class IndexingRepository {
  private readonly mutations: AtomicConfigurationMutation;
  private readonly reads: ScopedConfigurationRead;

  constructor(
    private readonly pool: Pool,
    identityRuntimeVerifier?: IdentityRuntimeVerifier,
    businessEvidence?: ConfigurationBusinessEvidence,
  ) {
    this.mutations = new AtomicConfigurationMutation(
      pool,
      identityRuntimeVerifier,
      businessEvidence,
    );
    this.reads = new ScopedConfigurationRead(pool);
  }

  async getIndexer(context: ReadContext): Promise<IndexerProfileRecord> {
    return this.reads.execute(context, async (client) => {
      const selected = await client.query<IndexerRow>(
        `select indexer_profile_id as "indexerProfileId",participant_id as "participantId",
          engine,engine_version as "engineVersion",method_profile_digest as "methodProfileDigest",
          state,revision::text,created_at::text as "createdAt",updated_at::text as "updatedAt"
         from control.indexer_profile where indexer_profile_id=$1`,
        [context.resourceId],
      );
      if (selected.rowCount !== 1) throw new ConfigurationRepositoryError('PC-FACT-4001');
      return indexerRecord(selected.rows[0]!);
    });
  }

  async listIndexers(
    context: ReadContext,
    request: ListRequest,
  ): Promise<PageResult<IndexerProfileRecord>> {
    return this.reads.execute(context, async (client) => {
      return selectPage(client, request, {
        table: 'control.indexer_profile',
        idColumn: 'indexer_profile_id',
        projection: `indexer_profile_id as "indexerProfileId",participant_id as "participantId",
          engine,engine_version as "engineVersion",method_profile_digest as "methodProfileDigest",
          state,revision::text,created_at::text as "createdAt",updated_at::text as "updatedAt"`,
        filterColumns: { state: 'state', engine: 'engine' },
        rowId: (row: IndexerRow) => row.indexerProfileId,
        rowUpdatedAt: (row: IndexerRow) => row.updatedAt,
        map: indexerRecord,
      });
    });
  }

  async createIndexer(
    context: MutationContext,
    input: {
      readonly engine: 'CLIENT_INDEXER' | 'EXTERNAL_ENGINE_ADAPTER';
      readonly engineVersion: string;
      readonly methodProfileDigest: string;
    },
  ): Promise<OperationRecord> {
    return this.mutations.execute(
      context,
      async (client, indexerProfileId) => {
        const scope = {
          participantId: context.authorization.participantId,
          privacyDomainId: context.authorization.privacyDomainId,
          aggregateId: indexerProfileId,
        };
        await client.query('select openpc.configuration_policy_provenance($1::uuid,$2::uuid)', [
          scope.participantId,
          scope.privacyDomainId,
        ]);
        const before = await readIndexerBusinessState(client, scope);
        const inserted = await client.query<IndexerRow>(
          `insert into control.indexer_profile
          (indexer_profile_id,participant_id,privacy_domain_id,engine,engine_version,
           method_profile_digest,policy_generation_digest)
         select $1,$2,$3,$4,$5,$6,openpc.configuration_policy_provenance($2::uuid,$3::uuid)
         returning indexer_profile_id as "indexerProfileId",participant_id as "participantId",
          engine,engine_version as "engineVersion",method_profile_digest as "methodProfileDigest",
          state,revision::text,created_at::text as "createdAt",updated_at::text as "updatedAt"`,
          [
            indexerProfileId,
            context.authorization.participantId,
            context.authorization.privacyDomainId,
            input.engine,
            input.engineVersion,
            input.methodProfileDigest,
          ],
        );
        if (inserted.rowCount !== 1) throw new ConfigurationRepositoryError('PC-DATA-6007');
        const after = await readIndexerBusinessState(client, scope);
        assertIndexerBusinessTransition({ kind: 'CREATE', ...input }, before, after);
        const result = indexerRecord(inserted.rows[0]!);
        return {
          result,
          revision: result.revision,
          outboxEventType: 'indexer-profile.registered.v1',
          businessState: bindIndexerTransition(context, scope, before, after),
        };
      },
      (client) => indexerProfileVersion(client, context),
    );
  }

  async updateIndexer(
    context: MutationContext,
    replacementDigest: string,
  ): Promise<OperationRecord> {
    return this.mutations.execute(
      context,
      async (client) => {
        const scope = {
          participantId: context.authorization.participantId,
          privacyDomainId: context.authorization.privacyDomainId,
          aggregateId: context.resourceId,
        };
        await client.query('select openpc.configuration_policy_provenance($1::uuid,$2::uuid)', [
          scope.participantId,
          scope.privacyDomainId,
        ]);
        const before = await readIndexerBusinessState(client, scope);
        const changed = await client.query<IndexerRow>(
          `update control.indexer_profile set method_profile_digest=$1,
         policy_generation_digest=openpc.configuration_policy_provenance(indexer_profile.participant_id,indexer_profile.privacy_domain_id),
         revision=revision+1,updated_at=clock_timestamp()
         where participant_id=$4 and privacy_domain_id=$5 and indexer_profile_id=$2 and revision=$3
         returning indexer_profile_id as "indexerProfileId",participant_id as "participantId",
           engine,engine_version as "engineVersion",method_profile_digest as "methodProfileDigest",
           state,revision::text,created_at::text as "createdAt",updated_at::text as "updatedAt"`,
          [
            replacementDigest,
            context.resourceId,
            context.expectedRevision,
            scope.participantId,
            scope.privacyDomainId,
          ],
        );
        if (changed.rowCount !== 1) throw new ConfigurationRepositoryError('PC-DATA-6007');
        const after = await readIndexerBusinessState(client, scope);
        try {
          assertIndexerBusinessTransition(
            { kind: 'UPDATE', expectedRevision: context.expectedRevision, replacementDigest },
            before,
            after,
          );
        } catch (error) {
          if (error instanceof IndexerBusinessTransitionError)
            throw new ConfigurationRepositoryError('PC-DATA-6007');
          throw error;
        }
        const result = indexerRecord(changed.rows[0]!);
        return {
          result,
          revision: result.revision,
          outboxEventType: 'indexer-profile.updated.v1',
          businessState: bindIndexerTransition(context, scope, before, after),
        };
      },
      (client) => indexerProfileVersion(client, context),
    );
  }

  async admitIndexer(context: MutationContext, inputDigest: string): Promise<OperationRecord> {
    return this.mutations.execute(context, async (client, _resourceId, operationId) => {
      const changed = await client.query<IndexerRow>(
        `with candidate as (
           update control.indexer_profile set state='SHADOW',
             policy_generation_digest=openpc.configuration_policy_provenance(indexer_profile.participant_id,indexer_profile.privacy_domain_id),
             revision=revision+1,updated_at=clock_timestamp()
            where indexer_profile_id=$1 and revision=$2 and method_profile_digest=$3
              and (state in ('REGISTERED','SHADOW') or (
                state in ('QUALIFIED','ACTIVE') and not exists (
                  select 1 from control.configuration_work prior
                  join control.idempotency_record result
                    on result.participant_id=prior.participant_id
                   and result.privacy_domain_id=prior.privacy_domain_id
                   and result.operation_id=prior.operation_id
                  where prior.participant_id=indexer_profile.participant_id
                    and prior.privacy_domain_id=indexer_profile.privacy_domain_id
                    and prior.resource_id=indexer_profile.indexer_profile_id
                    and prior.work_kind='INDEXER_ADMISSION' and prior.state='COMPLETED'
                    and prior.input_digest=indexer_profile.method_profile_digest
                    and result.terminal_state='COMMITTED'
                    and result.result_payload->>'state'='SUCCEEDED'
                    and result.result_aggregate_version=indexer_profile.revision)))
              and 1=(select count(*) from control.module_installation installation
                join control.module_version version on version.module_version_id=installation.module_version_id
                join control.module_registration module on module.module_id=version.module_id
                join control.runtime_configuration_input_current_metadata configuration
                  on configuration.module_installation_id=installation.module_installation_id
                 and configuration.active=true
               where installation.participant_id=indexer_profile.participant_id
                 and installation.privacy_domain_id=indexer_profile.privacy_domain_id
                 and installation.state='ENABLED' and module.module_id='pc.config.assets')
            returning *
         ), work as (
           insert into control.configuration_work
             (participant_id,privacy_domain_id,operation_id,work_kind,resource_id,input_digest,
              configuration_digest,policy_generation_digest)
           select participant_id,privacy_domain_id,$4,'INDEXER_ADMISSION',indexer_profile_id,$3,
             (select 'sha256:'||encode(configuration.configuration_digest,'hex')
                from control.module_installation installation
                join control.module_version version on version.module_version_id=installation.module_version_id
                join control.module_registration module on module.module_id=version.module_id
                join control.runtime_configuration_input_current_metadata configuration
                  on configuration.module_installation_id=installation.module_installation_id
                 and configuration.active=true
               where installation.participant_id=candidate.participant_id
                 and installation.privacy_domain_id=candidate.privacy_domain_id
                 and installation.state='ENABLED' and module.module_id='pc.config.assets'),
             policy_generation_digest
             from candidate
         )
         select indexer_profile_id as "indexerProfileId",participant_id as "participantId",
          engine,engine_version as "engineVersion",method_profile_digest as "methodProfileDigest",
          state,revision::text,created_at::text as "createdAt",updated_at::text as "updatedAt"
          from candidate`,
        [context.resourceId, context.expectedRevision, inputDigest, operationId],
      );
      if (changed.rowCount !== 1) throw new ConfigurationRepositoryError('PC-DATA-6007');
      const result = indexerRecord(changed.rows[0]!);
      return {
        result,
        revision: result.revision,
        outboxEventType: 'indexer-profile.admission-requested.v1',
        asynchronous: true,
      };
    });
  }

  async createProjection(
    context: MutationContext,
    input: {
      readonly indexerProfileId: string;
      readonly planDigest: string;
      readonly readiness: ProjectionPlanRecord['readiness'];
    },
  ): Promise<OperationRecord> {
    return this.mutations.execute(context, async (client, projectionPlanId) => {
      const inserted = await client.query<ProjectionPlanRecord>(
        `insert into control.projection_plan
          (projection_plan_id,participant_id,privacy_domain_id,indexer_profile_id,plan_digest,
           readiness,policy_generation_digest)
         select $1,$2,$3,$4,$5,'UNKNOWN',openpc.configuration_policy_provenance($2::uuid,$3::uuid)
         returning projection_plan_id as "projectionPlanId",indexer_profile_id as "indexerProfileId",
          plan_digest as "planDigest",state,readiness,revision::text,
          created_at::text as "createdAt",updated_at::text as "updatedAt"`,
        [
          projectionPlanId,
          context.authorization.participantId,
          context.authorization.privacyDomainId,
          input.indexerProfileId,
          input.planDigest,
        ],
      );
      const result = inserted.rows[0]!;
      return { result, revision: result.revision, outboxEventType: 'projection-plan.created.v1' };
    });
  }

  async getProjection(context: ReadContext): Promise<ProjectionPlanRecord> {
    return this.reads.execute(context, async (client) => {
      const selected = await client.query<ProjectionPlanRecord>(
        `select projection_plan_id as "projectionPlanId",indexer_profile_id as "indexerProfileId",
          plan_digest as "planDigest",state,readiness,revision::text,
          created_at::text as "createdAt",updated_at::text as "updatedAt"
         from control.projection_plan where projection_plan_id=$1`,
        [context.resourceId],
      );
      if (selected.rowCount !== 1) throw new ConfigurationRepositoryError('PC-FACT-4001');
      return projectionRecord(selected.rows[0]!);
    });
  }

  async listProjections(
    context: ReadContext,
    request: ListRequest,
  ): Promise<PageResult<ProjectionPlanRecord>> {
    return this.reads.execute(context, async (client) => {
      return selectPage(client, request, {
        table: 'control.projection_plan',
        idColumn: 'projection_plan_id',
        projection: `projection_plan_id as "projectionPlanId",indexer_profile_id as "indexerProfileId",
          plan_digest as "planDigest",state,readiness,revision::text,
          created_at::text as "createdAt",updated_at::text as "updatedAt"`,
        filterColumns: { state: 'state', readiness: 'readiness' },
        rowId: (row: ProjectionPlanRecord) => row.projectionPlanId,
        rowUpdatedAt: (row: ProjectionPlanRecord) => row.updatedAt,
        map: projectionRecord,
      });
    });
  }

  async updateProjection(
    context: MutationContext,
    replacementDigest: string,
  ): Promise<OperationRecord> {
    return this.changeProjection(
      context,
      'projection-plan.updated.v1',
      'DRAFT',
      undefined,
      replacementDigest,
    );
  }

  async recoverProjection(context: MutationContext, inputDigest: string): Promise<OperationRecord> {
    return this.mutations.execute(context, async (client, _resourceId, operationId) => {
      const changed = await client.query<ProjectionPlanRecord>(
        `with candidate as (
           update control.projection_plan set state='DRAFT',readiness='UNKNOWN',
             policy_generation_digest=openpc.configuration_policy_provenance(projection_plan.participant_id,projection_plan.privacy_domain_id),
             revision=revision+1,updated_at=clock_timestamp()
            where projection_plan_id=$1 and revision=$2 and plan_digest=$3 and state<>'RETIRED'
              and 1=(select count(*) from control.module_installation installation
                join control.module_version version on version.module_version_id=installation.module_version_id
                join control.module_registration module on module.module_id=version.module_id
                join control.runtime_configuration_input_current_metadata configuration
                  on configuration.module_installation_id=installation.module_installation_id
                 and configuration.active=true
               where installation.participant_id=projection_plan.participant_id
                 and installation.privacy_domain_id=projection_plan.privacy_domain_id
                 and installation.state='ENABLED' and module.module_id='pc.config.assets')
            returning *
         ), work as (
           insert into control.configuration_work
             (participant_id,privacy_domain_id,operation_id,work_kind,resource_id,input_digest,
              configuration_digest,policy_generation_digest)
           select participant_id,privacy_domain_id,$4,'PROJECTION_VALIDATION',projection_plan_id,$3,
             (select 'sha256:'||encode(configuration.configuration_digest,'hex')
                from control.module_installation installation
                join control.module_version version on version.module_version_id=installation.module_version_id
                join control.module_registration module on module.module_id=version.module_id
                join control.runtime_configuration_input_current_metadata configuration
                  on configuration.module_installation_id=installation.module_installation_id
                 and configuration.active=true
               where installation.participant_id=candidate.participant_id
                 and installation.privacy_domain_id=candidate.privacy_domain_id
                 and installation.state='ENABLED' and module.module_id='pc.config.assets'),
             policy_generation_digest
             from candidate
         )
         select projection_plan_id as "projectionPlanId",indexer_profile_id as "indexerProfileId",
          plan_digest as "planDigest",state,readiness,revision::text,
          created_at::text as "createdAt",updated_at::text as "updatedAt" from candidate`,
        [context.resourceId, context.expectedRevision, inputDigest, operationId],
      );
      if (changed.rowCount !== 1) throw new ConfigurationRepositoryError('PC-DATA-6007');
      const result = changed.rows[0]!;
      return {
        result,
        revision: result.revision,
        outboxEventType: 'projection-plan.validation-requested.v1',
        asynchronous: true,
      };
    });
  }

  private async changeProjection(
    context: MutationContext,
    eventType: string,
    state: ProjectionPlanRecord['state'],
    readiness: ProjectionPlanRecord['readiness'] | undefined,
    digest: string,
  ): Promise<OperationRecord> {
    return this.mutations.execute(context, async (client) => {
      const changed = await client.query<ProjectionPlanRecord>(
        `update control.projection_plan set plan_digest=case when $3::text is null then $1 else plan_digest end,state=$2,
          readiness=coalesce($3::text,readiness),policy_generation_digest=openpc.configuration_policy_provenance(projection_plan.participant_id,projection_plan.privacy_domain_id),
          revision=revision+1,updated_at=clock_timestamp()
         where projection_plan_id=$4 and revision=$5 and state<>'RETIRED'
           and ($3::text is null or plan_digest=$1)
         returning projection_plan_id as "projectionPlanId",indexer_profile_id as "indexerProfileId",
          plan_digest as "planDigest",state,readiness,revision::text,
          created_at::text as "createdAt",updated_at::text as "updatedAt"`,
        [digest, state, readiness ?? null, context.resourceId, context.expectedRevision],
      );
      if (changed.rowCount !== 1) throw new ConfigurationRepositoryError('PC-DATA-6007');
      const result = changed.rows[0]!;
      return { result, revision: result.revision, outboxEventType: eventType };
    });
  }
}

function bindIndexerTransition(
  context: MutationContext,
  scope: Parameters<typeof readIndexerBusinessState>[1],
  before: Awaited<ReturnType<typeof readIndexerBusinessState>>,
  after: Awaited<ReturnType<typeof readIndexerBusinessState>>,
) {
  const profile = businessTransitionProfileForOperation(
    context.catalogOperationId,
    before?.policyGenerationDigest === null || after?.policyGenerationDigest === null ? 2 : 1,
  );
  if (profile === undefined || profile.aggregateType !== 'indexer-profile')
    throw new ConfigurationRepositoryError('PC-DATA-6007');
  const binding = {
    ...scope,
    aggregateType: profile.aggregateType,
    profileDigest: Buffer.from(profile.profileDigest.slice(7), 'hex'),
  };
  return {
    before: bindIndexerBusinessState(binding, before, profile.profileVersion),
    after: bindIndexerBusinessState(binding, after, profile.profileVersion),
  };
}

/** Hold the same generation fence as the write before choosing its immutable receipt profile. */
async function indexerProfileVersion(
  client: PoolClient,
  context: MutationContext,
): Promise<number> {
  const selected = await client.query<{ digest: string | null; absentBefore: boolean }>(
    `select (select 'sha256:'||encode(generation_digest,'hex') from control.policy_generation
       where participant_id=$1 and privacy_domain_id=$2 and active and state='ACTIVE') as digest,
      exists(select 1 from control.indexer_profile where participant_id=$1 and privacy_domain_id=$2
        and indexer_profile_id=$3 and policy_generation_digest is null) as "absentBefore"`,
    [
      context.authorization.participantId,
      context.authorization.privacyDomainId,
      context.resourceId,
    ],
  );
  if (selected.rowCount !== 1) throw new ConfigurationRepositoryError('PC-DATA-6007');
  return selected.rows[0]!.digest === null || selected.rows[0]!.absentBefore ? 2 : 1;
}
