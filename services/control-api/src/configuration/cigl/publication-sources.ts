import type { PoolClient } from 'pg';
import { ConfigurationRepositoryError } from '../persistence/types.js';

/** Readback may propose exact current source pins, but grants no authority.
 * The mutation and Fleet must reacquire their fences and reject changed pins. */
export async function readPublicationSources(
  client: PoolClient,
  profileId: string,
  revision: string,
  participant: string,
  privacy: string,
) {
  const parameters = [profileId, revision, participant, privacy];
  const selected = await client.query<{
    target_id: string;
    target_revision: string;
    capsule_digest: string;
    participant_epoch: string;
  }>(
    `select target.runtime_target_id::text target_id,target.revision::text target_revision,
      target.active_generation_digest capsule_digest,participant.authority_epoch::text participant_epoch
     from control.cigl_profile_version version
     join control.cigl_analysis analysis on analysis.analysis_id=version.analysis_id
      and analysis.participant_id=version.participant_id and analysis.privacy_domain_id=version.privacy_domain_id
     join control.runtime_target target on target.runtime_target_id=analysis.runtime_target_id
      and target.participant_id=analysis.participant_id and target.privacy_domain_id=analysis.privacy_domain_id
     join control.participant participant on participant.participant_id=version.participant_id
     where version.profile_id=$1 and version.revision=$2 and version.participant_id=$3 and version.privacy_domain_id=$4
      and version.state='COMPILED' and version.dependency_paths_digest is not null
      and target.state='ACTIVE_MATCHED' and target.active_generation_digest=target.desired_generation_digest
      and openpc.cigl_profile_has_installed_lineage(version.profile_id,version.revision,
        target.runtime_target_id,target.active_generation_digest,target.policy_generation_digest)
      and participant.state='ACTIVE' and participant.archived_at is null and participant.authority_epoch>0
      and not exists(select 1 from control.cigl_profile_method_source retained
        left join control.contract_method_policy method on method.contract_method_policy_id=retained.contract_method_policy_id
         and method.participant_id=retained.participant_id and method.privacy_domain_id=retained.privacy_domain_id
        left join control.contract_runtime_binding binding on binding.runtime_binding_id=retained.runtime_binding_id
         and binding.participant_id=retained.participant_id and binding.privacy_domain_id=retained.privacy_domain_id
        where retained.profile_id=version.profile_id and retained.profile_revision=version.revision
         and (method.contract_method_policy_id is null or method.state<>'ACTIVE' or method.revision<>retained.method_revision
          or binding.runtime_binding_id is null or binding.state<>'BOUND' or binding.revision<>retained.binding_revision))`,
    parameters,
  );
  if (selected.rowCount === 0) return null;
  if (selected.rowCount !== 1) throw new ConfigurationRepositoryError('PC-FACT-4001');
  const grants = await client.query<{ source: unknown }>(
    `select jsonb_build_object('grantId',grant_row.grant_id::text,'revision',grant_row.revision::text,
      'digest',substring(grant_row.grant_digest from 8)) source
     from control.cigl_method_access_grants grant_row
     where grant_row.participant_id=$3 and grant_row.privacy_domain_id=$4
      and exists(select 1 from control.cigl_profile_dependency_path path
       join control.contract_method_policy method on method.contract_method_policy_id::text=path.document->>'contractMethodPolicyId'
        and method.participant_id=path.participant_id and method.privacy_domain_id=path.privacy_domain_id
       where path.profile_id=$1 and path.profile_revision=$2 and path.participant_id=$3 and path.privacy_domain_id=$4
        and method.runtime_binding_id=grant_row.runtime_binding_id and method.selector=grant_row.selector)
     order by grant_row.grant_id limit 4097`,
    parameters,
  );
  if (grants.rows.length > 4096) throw new ConfigurationRepositoryError('PC-DATA-6004');
  return { target: selected.rows[0]!, grants: grants.rows.map((row) => row.source) };
}
