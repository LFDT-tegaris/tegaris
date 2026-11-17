import type { PoolClient } from 'pg';
import { ConfigurationRepositoryError, type MutationContext } from '../persistence/types.js';
import type { ActivateCiglProfiles } from './activation-contract.js';
import { readCiglProfile } from './profile-readback.js';

/** Freeze exact reviewed selections inside the ordinary authenticated mutation.
 * This queues activation; only Fleet and the target can produce its effect. */
export async function fenceCiglActivationSources(
  client: PoolClient,
  context: MutationContext,
  input: ActivateCiglProfiles,
) {
  if (
    context.actionIntentId !== 'ACT-CIGL_PROFILES_ACTIVATE_RESOURCE-V1' ||
    input.targetRef !== `urn:openpc:resource:${context.resourceId}`
  )
    throw new ConfigurationRepositoryError('PC-AUTH-0005');
  // AtomicConfigurationMutation already holds Participant and authority roots.
  await client.query('select openpc.lock_cigl_grant_sources()');
  const roots = new Set<string>();
  for (const selection of input.profiles) {
    const selected = await client.query<{ analysis_id: string; root_id: string }>(
      `select version.analysis_id::text,profile.root_contract_method_policy_id::text root_id
       from control.cigl_profile_version version join control.cigl_method_profile profile
        on profile.profile_id=version.profile_id and profile.participant_id=version.participant_id and profile.privacy_domain_id=version.privacy_domain_id
       where version.profile_id=$1 and version.revision=$2 and version.participant_id=$3 and version.privacy_domain_id=$4 and version.state='COMPILED'`,
      [
        selection.profileId.slice('urn:openpc:resource:'.length),
        selection.profileRevision,
        context.authorization.participantId,
        context.authorization.privacyDomainId,
      ],
    );
    const source = selected.rows[0];
    if (selected.rowCount !== 1 || !source || roots.has(source.root_id))
      throw new ConfigurationRepositoryError('PC-DATA-6007');
    roots.add(source.root_id);
    await client.query(
      `select method.contract_method_policy_id from control.cigl_profile_method_source retained
       join control.contract_method_policy method on method.contract_method_policy_id=retained.contract_method_policy_id
        and method.participant_id=retained.participant_id and method.privacy_domain_id=retained.privacy_domain_id
       join control.contract_runtime_binding binding on binding.runtime_binding_id=retained.runtime_binding_id
        and binding.participant_id=retained.participant_id and binding.privacy_domain_id=retained.privacy_domain_id
       where retained.profile_id=$1 and retained.profile_revision=$2
       order by method.contract_method_policy_id for share of method,binding`,
      [selection.profileId.slice('urn:openpc:resource:'.length), selection.profileRevision],
    );
    const profile = await readCiglProfile(
      client,
      source.analysis_id,
      context.authorization.participantId,
      context.authorization.privacyDomainId,
      true,
    );
    if (
      profile?.profileId !== selection.profileId ||
      profile.revision !== selection.profileRevision ||
      profile.result?.profileDigest !== selection.profileDigest ||
      profile.result.artifactDigest !== selection.compilationArtifactDigest ||
      profile.currentSources?.targetRuntimeId !== input.targetRef ||
      profile.currentSources.targetRevision !== input.expectedRevision ||
      profile.currentSources.installedCapsuleDigest !== input.expectedGenerationDigest ||
      profile.currentSources.participantEpoch !== input.participantEpoch ||
      profile.currentSources.grantSourcesDigest !== selection.grantSourcesDigest
    )
      throw new ConfigurationRepositoryError('PC-DATA-6007');
  }
  const target = await client.query(
    `select runtime_target_id from control.runtime_target where runtime_target_id=$1
      and revision=$2 and active_generation_digest=$3 and desired_generation_digest=$3
      and state='ACTIVE_MATCHED' for update`,
    [context.resourceId, input.expectedRevision, input.expectedGenerationDigest],
  );
  if (target.rowCount !== 1) throw new ConfigurationRepositoryError('PC-DATA-6007');
}
