import type { Pool } from 'pg';
import type { IdentityRuntimeVerifier } from '../../../../identity-service/src/domain/identity-runtime-crypto.js';

import { type ListRequest, type PageResult, selectPage } from '../pagination.js';
import { AtomicConfigurationMutation } from '../persistence/atomic-mutation.js';
import { ScopedConfigurationRead, type ReadContext } from '../persistence/scoped-read.js';
import {
  ConfigurationRepositoryError,
  type MutationContext,
  type OperationRecord,
} from '../persistence/types.js';

export interface ProviderProfileRecord {
  readonly providerProfileId: string;
  readonly participantId: string;
  readonly chainId: string;
  readonly endpointSecretRef: string;
  readonly behaviorFingerprint: string;
  readonly state: 'REGISTERED' | 'SHADOW' | 'QUALIFIED' | 'ACTIVE' | 'QUARANTINED' | 'RETIRED';
  readonly authority: 'NEVER_GRANTS';
  readonly admissionScope?: 'FULL_CORPUS' | 'BOUNDED_QA' | null;
  readonly historicalReorgConformance?: 'OBSERVED' | 'NOT_TESTED' | null;
  readonly revision: string;
  readonly createdAt: string;
  readonly updatedAt: string;
}

type ProviderRow = Omit<ProviderProfileRecord, 'authority'>;

function record(row: ProviderRow): ProviderProfileRecord {
  return {
    ...row,
    admissionScope: row.admissionScope ?? null,
    historicalReorgConformance: row.historicalReorgConformance ?? null,
    providerProfileId: `urn:openpc:resource:${row.providerProfileId}`,
    participantId: `urn:openpc:participant:${row.participantId}`,
    createdAt: new Date(row.createdAt).toISOString().replace(/\.([0-9]{3})Z$/u, '.$1000Z'),
    updatedAt: new Date(row.updatedAt).toISOString().replace(/\.([0-9]{3})Z$/u, '.$1000Z'),
    authority: 'NEVER_GRANTS',
  };
}

const observationProjection = `
  (select o.observation->>'admission_scope' from control.provider_probe_observation o
    where o.observation_id=provider_profile.qualification_observation_id
      and o.provider_profile_id=provider_profile.provider_profile_id
      and o.input_digest=provider_profile.behavior_fingerprint
      and o.state='OBSERVED') as "admissionScope",
  (select o.observation->>'historical_reorg_conformance' from control.provider_probe_observation o
    where o.observation_id=provider_profile.qualification_observation_id
      and o.provider_profile_id=provider_profile.provider_profile_id
      and o.input_digest=provider_profile.behavior_fingerprint
      and o.state='OBSERVED') as "historicalReorgConformance"`;

export class ProviderProfileRepository {
  private readonly mutations: AtomicConfigurationMutation;
  private readonly reads: ScopedConfigurationRead;

  constructor(
    private readonly pool: Pool,
    identityRuntimeVerifier?: IdentityRuntimeVerifier,
  ) {
    this.mutations = new AtomicConfigurationMutation(pool, identityRuntimeVerifier);
    this.reads = new ScopedConfigurationRead(pool);
  }

  async get(context: ReadContext): Promise<ProviderProfileRecord> {
    return this.reads.execute(context, async (client) => {
      const selected = await client.query<ProviderRow>(
        `select provider_profile_id as "providerProfileId",participant_id as "participantId",
          chain_id as "chainId",endpoint_secret_ref as "endpointSecretRef",
          behavior_fingerprint as "behaviorFingerprint",state,revision::text,
          created_at::text as "createdAt",updated_at::text as "updatedAt",${observationProjection}
         from control.provider_profile where provider_profile_id=$1`,
        [context.resourceId],
      );
      if (selected.rowCount !== 1) throw new ConfigurationRepositoryError('PC-FACT-4001');
      return record(selected.rows[0]!);
    });
  }

  async list(
    context: ReadContext,
    request: ListRequest,
  ): Promise<PageResult<ProviderProfileRecord>> {
    return this.reads.execute(context, async (client) => {
      return selectPage(client, request, {
        table: 'control.provider_profile',
        idColumn: 'provider_profile_id',
        projection: `provider_profile_id as "providerProfileId",participant_id as "participantId",
          chain_id as "chainId",endpoint_secret_ref as "endpointSecretRef",
          behavior_fingerprint as "behaviorFingerprint",state,revision::text,
          created_at::text as "createdAt",updated_at::text as "updatedAt",${observationProjection}`,
        filterColumns: { state: 'state' },
        rowId: (row: ProviderRow) => row.providerProfileId,
        rowUpdatedAt: (row: ProviderRow) => row.updatedAt,
        map: record,
      });
    });
  }

  async create(
    context: MutationContext,
    input: {
      readonly chainId: string;
      readonly endpointSecretRef: string;
      readonly behaviorFingerprint: string;
    },
  ): Promise<OperationRecord> {
    return this.mutations.execute(context, async (client, providerProfileId) => {
      const inserted = await client.query<ProviderRow>(
        `insert into control.provider_profile
          (provider_profile_id,participant_id,privacy_domain_id,chain_id,endpoint_secret_ref,
           behavior_fingerprint,policy_generation_digest)
         select $1,$2,$3,$4,$5,$6,openpc.configuration_policy_provenance($2::uuid,$3::uuid)
         returning provider_profile_id as "providerProfileId",participant_id as "participantId",
           chain_id as "chainId",endpoint_secret_ref as "endpointSecretRef",
           behavior_fingerprint as "behaviorFingerprint",state,revision::text,
           created_at::text as "createdAt",updated_at::text as "updatedAt"`,
        [
          providerProfileId,
          context.authorization.participantId,
          context.authorization.privacyDomainId,
          input.chainId,
          input.endpointSecretRef,
          input.behaviorFingerprint,
        ],
      );
      const result = record(inserted.rows[0]!);
      return {
        result,
        revision: result.revision,
        outboxEventType: 'provider-profile.registered.v1',
      };
    });
  }

  async updateDigest(
    context: MutationContext,
    replacementDigest: string,
  ): Promise<OperationRecord> {
    return this.update(
      context,
      'provider-profile.updated.v1',
      `update control.provider_profile set behavior_fingerprint=$1,state='REGISTERED',
         qualification_observation_id=null,
         policy_generation_digest=openpc.configuration_policy_provenance(provider_profile.participant_id,provider_profile.privacy_domain_id),
         revision=revision+1,updated_at=clock_timestamp()
       where provider_profile_id=$2 and revision=$3 and state<>'RETIRED'`,
      [replacementDigest, context.resourceId, context.expectedRevision],
    );
  }

  async qualify(context: MutationContext, inputDigest: string): Promise<OperationRecord> {
    return this.mutations.execute(context, async (client, _resourceId, operationId) => {
      const changed = await client.query<ProviderRow>(
        `with candidate as (
           update control.provider_profile set state='SHADOW',
             qualification_observation_id=(select observation.observation_id
               from control.provider_probe_observation observation
              where observation.provider_profile_id=provider_profile.provider_profile_id
                and observation.observed_revision=provider_profile.revision
                and observation.input_digest=provider_profile.behavior_fingerprint
                and observation.state='OBSERVED' and observation.valid_until>clock_timestamp()),
             policy_generation_digest=openpc.configuration_policy_provenance(provider_profile.participant_id,provider_profile.privacy_domain_id),
             revision=revision+1,updated_at=clock_timestamp()
            where provider_profile_id=$1 and revision=$2 and behavior_fingerprint=$3
              and state='SHADOW' and qualification_observation_id is null
              and 1=(select count(*) from control.provider_probe_observation observation
                join control.module_installation installation
                  on installation.participant_id=provider_profile.participant_id
                 and installation.privacy_domain_id=provider_profile.privacy_domain_id
                 and installation.state='ENABLED'
                join control.module_version version on version.module_version_id=installation.module_version_id
                 and version.module_id='pc.config.assets'
                join control.runtime_configuration_input_current_metadata configuration
                  on configuration.module_installation_id=installation.module_installation_id
                 and configuration.active=true
               where observation.provider_profile_id=provider_profile.provider_profile_id
                 and observation.observed_revision=provider_profile.revision
                 and observation.input_digest=provider_profile.behavior_fingerprint
                 and observation.configuration_digest='sha256:'||encode(configuration.configuration_digest,'hex')
                 and observation.state='OBSERVED' and observation.valid_until>clock_timestamp())
              and 1=(select count(*) from control.module_installation installation
                join control.module_version version on version.module_version_id=installation.module_version_id
                join control.module_registration module on module.module_id=version.module_id
                join control.runtime_configuration_input_current_metadata configuration
                  on configuration.module_installation_id=installation.module_installation_id
                 and configuration.active=true
               where installation.participant_id=provider_profile.participant_id
                 and installation.privacy_domain_id=provider_profile.privacy_domain_id
                 and installation.state='ENABLED' and module.module_id='pc.config.assets')
            returning *
         ), work as (
           insert into control.configuration_work
             (participant_id,privacy_domain_id,operation_id,work_kind,resource_id,input_digest,
              configuration_digest,policy_generation_digest)
           select participant_id,privacy_domain_id,$4,'PROVIDER_QUALIFICATION',provider_profile_id,$3,
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
         select provider_profile_id as "providerProfileId",participant_id as "participantId",
          chain_id as "chainId",endpoint_secret_ref as "endpointSecretRef",
          behavior_fingerprint as "behaviorFingerprint",state,revision::text,
          created_at::text as "createdAt",updated_at::text as "updatedAt" from candidate`,
        [context.resourceId, context.expectedRevision, inputDigest, operationId],
      );
      if (changed.rowCount !== 1) throw new ConfigurationRepositoryError('PC-DATA-6007');
      const result = record(changed.rows[0]!);
      return {
        result,
        revision: result.revision,
        outboxEventType: 'provider-profile.qualification-requested.v1',
        asynchronous: true,
      };
    });
  }

  async quarantine(context: MutationContext): Promise<OperationRecord> {
    return this.update(
      context,
      'provider-profile.quarantined.v1',
      `update control.provider_profile set state='QUARANTINED',qualification_observation_id=null,
         revision=revision+1,updated_at=clock_timestamp()
       where provider_profile_id=$1 and revision=$2 and state<>'RETIRED'`,
      [context.resourceId, context.expectedRevision],
    );
  }

  private async update(
    context: MutationContext,
    eventType: string,
    statement: string,
    values: readonly unknown[],
  ): Promise<OperationRecord> {
    return this.mutations.execute(context, async (client) => {
      const changed = await client.query<ProviderRow>(
        `${statement} returning provider_profile_id as "providerProfileId",participant_id as "participantId",
          chain_id as "chainId",endpoint_secret_ref as "endpointSecretRef",
          behavior_fingerprint as "behaviorFingerprint",state,revision::text,
          created_at::text as "createdAt",updated_at::text as "updatedAt"`,
        [...values],
      );
      if (changed.rowCount !== 1) throw new ConfigurationRepositoryError('PC-DATA-6007');
      const result = record(changed.rows[0]!);
      return { result, revision: result.revision, outboxEventType: eventType };
    });
  }
}
