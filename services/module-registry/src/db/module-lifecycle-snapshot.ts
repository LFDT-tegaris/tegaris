import type { PoolClient } from 'pg';
import { ContractError } from '../domain/errors.js';
import {
  selectRelease,
  type StoredRelease,
  type ModuleReleaseVerifier,
} from './module-release-store.js';

interface Configuration {
  id: string;
  configurationId: string;
  generation: string;
  active: boolean;
  digest: Buffer;
  activeManifest: Buffer | null;
  operationId: string | null;
  evaluationDigest: Buffer | null;
}

/** Same scope lock as admission, held until the business commit or consumer fence ends. */
export async function readVerifiedModuleLifecycleSnapshot(
  client: Pick<PoolClient, 'query'>,
  participant: string,
  privacy: string,
  verify: ModuleReleaseVerifier,
) {
  const selected = await client.query<StoredRelease>(
    `${selectRelease}
    where installation.participant_id=$1 and installation.privacy_domain_id=$2
    and installation.state in ('ADMITTED','INSTALLED_DISABLED','ENABLED')
    and version.release_payload_cbor is not null order by version.module_id`,
    [participant, privacy],
  );
  const configurations = await client.query<Configuration>(
    `select installation.module_installation_id::text id,configuration.generation_id::text as "configurationId",
    configuration.generation::text,configuration.active,configuration.configuration_digest digest,
    installation.active_manifest_digest as "activeManifest",installation.lifecycle_operation_id::text as "operationId",
    installation.lifecycle_evaluation_digest as "evaluationDigest"
    from control.module_installation installation join control.module_configuration_generation configuration using(module_installation_id)
    where installation.participant_id=$1 and installation.privacy_domain_id=$2
      and configuration.participant_id=$1 and configuration.privacy_domain_id=$2`,
    [participant, privacy],
  );
  const now = Date.now();
  return selected.rows.map((stored) => {
    const matches = configurations.rows.filter((row) => row.id === stored.moduleInstallationId);
    const configuration = matches[0];
    const release = verify(stored, now);
    if (
      matches.length !== 1 ||
      !configuration ||
      !configuration.digest.equals(release.configurationDigest)
    )
      throw new ContractError('PC-MODULE-7003');
    return { stored, release, configuration };
  });
}
