import type { PoolClient } from 'pg';
import { sha256 } from '../digest.js';
import type { MutationContext } from '../persistence/types.js';
import { ConfigurationRepositoryError } from '../persistence/types.js';

/** Review acceptance creates a draft version and the existing durable work
 * item in one transaction. There is no caller-supplied compiled artifact. */
export async function enqueueCiglProfile(
  client: PoolClient,
  context: MutationContext,
  analysisId: string,
  operationId: string,
) {
  await client.query('select openpc.lock_cigl_grant_sources()');
  await client.query(
    `insert into control.cigl_method_profile(participant_id,privacy_domain_id,root_contract_method_policy_id)
    select participant_id,privacy_domain_id,contract_method_policy_id from control.cigl_analysis
    where analysis_id=$1 and state='REVIEWED' and revision=3 and publication_operation_id=$2
    on conflict(participant_id,privacy_domain_id,root_contract_method_policy_id) do nothing`,
    [analysisId, operationId],
  );
  const owner = await client.query<{ profile_id: string }>(
    `select profile.profile_id from control.cigl_method_profile profile
    join control.cigl_analysis analysis on analysis.participant_id=profile.participant_id
      and analysis.privacy_domain_id=profile.privacy_domain_id and analysis.contract_method_policy_id=profile.root_contract_method_policy_id
    where analysis.analysis_id=$1 for update of profile`,
    [analysisId],
  );
  if (owner.rowCount !== 1) throw new ConfigurationRepositoryError('PC-FACT-4001');
  const queued = await client.query<{ configuration_work_id: string }>(
    `insert into control.configuration_work
    (participant_id,privacy_domain_id,operation_id,work_kind,resource_id,input_digest,configuration_digest,
     runtime_target_id,generation_digest,policy_generation_digest)
    select analysis.participant_id,analysis.privacy_domain_id,$2,'CIGL_PROFILE_COMPILATION',analysis.analysis_id,$3,
      prior.configuration_digest,analysis.runtime_target_id,analysis.definition->>'expectedGenerationDigest',analysis.policy_generation_digest
    from control.cigl_analysis analysis join control.runtime_activation_observation observation
      on observation.participant_id=analysis.participant_id and observation.privacy_domain_id=analysis.privacy_domain_id
      and observation.runtime_target_id=analysis.runtime_target_id and observation.capsule_digest=analysis.capsule_digest
      and observation.capsule_digest=analysis.definition->>'expectedGenerationDigest'
    join control.configuration_work prior on prior.configuration_work_id=observation.configuration_work_id
      and prior.participant_id=observation.participant_id and prior.privacy_domain_id=observation.privacy_domain_id
      and prior.work_kind='RUNTIME_ACTIVATION' and prior.runtime_target_id=observation.runtime_target_id
      and prior.runtime_configuration_generation_id=observation.runtime_configuration_generation_id
      and prior.generation_digest=observation.generation_digest
    where analysis.analysis_id=$1 and analysis.state='REVIEWED' and analysis.revision=3
      and analysis.publication_operation_id=$2 returning configuration_work_id`,
    [analysisId, operationId, sha256(context.candidate)],
  );
  if (queued.rowCount !== 1) throw new ConfigurationRepositoryError('PC-FACT-4001');
  await client.query(
    `insert into control.cigl_profile_version(profile_id,revision,participant_id,privacy_domain_id,analysis_id,configuration_work_id,review_digest)
    select $1,coalesce((select max(revision) from control.cigl_profile_version where profile_id=$1),0)+1,
      participant_id,privacy_domain_id,analysis_id,$3,review_digest from control.cigl_analysis where analysis_id=$2`,
    [owner.rows[0]!.profile_id, analysisId, queued.rows[0]!.configuration_work_id],
  );
}
