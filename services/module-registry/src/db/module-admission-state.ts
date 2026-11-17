import { createHash } from 'node:crypto';
import { businessTransitionProfileForOperation } from '@openpc/security-kernel';
import {
  transitionStatePreimage,
  type CborValue,
} from '@openpc/security-kernel/business-transition/state';
import type { PoolClient } from 'pg';
import type { MutationContext } from '../../../control-api/src/configuration/persistence/types.js';
import { ContractError } from '../domain/errors.js';

export interface AdmissionState {
  moduleId: string;
  semanticVersion: string;
  manifestDigest: Buffer;
  dependencyDigest: Buffer;
  configurationDigest: Buffer;
  state: string;
  activeManifestDigest: Buffer | null;
  generation: string;
  active: boolean;
  revision: string;
  evaluationDigest?: Buffer | null;
}

/** Read the actual rows inside the admission transaction, never the response DTO. */
export async function readModuleAdmissionState(client: PoolClient, context: MutationContext) {
  const selected = await client.query<AdmissionState>(
    `select version.module_id as "moduleId",version.semantic_version as "semanticVersion",
      version.manifest_digest as "manifestDigest",installation.admission_dependency_digest as "dependencyDigest",
      configuration.configuration_digest as "configurationDigest",installation.state,
      installation.active_manifest_digest as "activeManifestDigest",configuration.generation::text as generation,
      configuration.active,installation.aggregate_version::text as revision,
      installation.lifecycle_evaluation_digest as "evaluationDigest"
     from control.module_installation installation
     join control.module_version version using(module_version_id)
     join control.module_configuration_generation configuration using(module_installation_id)
     where installation.participant_id=$1 and installation.privacy_domain_id=$2
       and installation.module_installation_id=$3
       and configuration.participant_id=installation.participant_id
       and configuration.privacy_domain_id=installation.privacy_domain_id`,
    [
      context.authorization.participantId,
      context.authorization.privacyDomainId,
      context.resourceId,
    ],
  );
  if (selected.rowCount === 0) return undefined;
  if (selected.rowCount !== 1) throw new ContractError('PC-MODULE-7003');
  return selected.rows[0]!;
}

export function bindModuleAdmissionTransition(
  context: MutationContext,
  before: AdmissionState | undefined,
  after: AdmissionState | undefined,
  expected: Pick<
    AdmissionState,
    'moduleId' | 'semanticVersion' | 'manifestDigest' | 'dependencyDigest' | 'configurationDigest'
  >,
) {
  const profile = businessTransitionProfileForOperation(context.catalogOperationId);
  if (
    profile?.profileId !== 'pc.control.module.register' ||
    context.aggregateType !== profile.aggregateType ||
    before !== undefined ||
    after === undefined ||
    after.moduleId !== expected.moduleId ||
    after.semanticVersion !== expected.semanticVersion ||
    after.state !== 'ADMITTED' ||
    after.revision !== '1' ||
    after.generation !== '1' ||
    after.active !== false ||
    after.activeManifestDigest !== null ||
    !after.manifestDigest.equals(expected.manifestDigest) ||
    !after.dependencyDigest.equals(expected.dependencyDigest) ||
    !after.configurationDigest.equals(expected.configurationDigest)
  )
    throw new ContractError('PC-MODULE-7003');
  const scope = {
    profileDigest: Buffer.from(profile.profileDigest.slice(7), 'hex'),
    participantId: context.authorization.participantId,
    privacyDomainId: context.authorization.privacyDomainId,
    aggregateType: profile.aggregateType,
    aggregateId: context.resourceId,
  };
  const bind = (existence: 0 | 1, projection: Map<number, CborValue>) => {
    const revision = BigInt(existence);
    const preimage = transitionStatePreimage(scope, existence, revision, projection);
    return {
      preimage,
      reference: {
        existence,
        revision,
        stateDigest: createHash('sha256').update(preimage).digest(),
      },
    };
  };
  return {
    before: bind(0, new Map()),
    after: bind(
      1,
      new Map<number, CborValue>([
        [0, after.moduleId],
        [1, after.semanticVersion],
        [2, after.manifestDigest],
        [3, after.dependencyDigest],
        [4, after.configurationDigest],
        [5, after.state],
        [6, 0n],
        [7, 1n],
        [8, 0n],
      ]),
    ),
  };
}
