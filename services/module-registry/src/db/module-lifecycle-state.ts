import { createHash } from 'node:crypto';
import { businessTransitionProfileForOperation } from '@openpc/security-kernel';
import {
  transitionStatePreimage,
  type CborValue,
} from '@openpc/security-kernel/business-transition/state';
import type { MutationContext } from '../../../control-api/src/configuration/persistence/types.js';
import type { AdmissionState } from './module-admission-state.js';
import { ContractError } from '../domain/errors.js';

export function bindModuleLifecycleTransition(
  context: MutationContext,
  before: AdmissionState,
  after: AdmissionState,
) {
  const enable = context.catalogOperationId === 'MOD-OP-ENABLE';
  const disable = context.catalogOperationId === 'MOD-OP-DISABLE';
  const profile = businessTransitionProfileForOperation(context.catalogOperationId);
  if (
    profile?.profileId !==
      `pc.control.module.${disable ? 'disable' : enable ? 'enable' : 'install'}` ||
    context.aggregateType !== profile.aggregateType ||
    before.state !== (disable ? 'ENABLED' : enable ? 'INSTALLED_DISABLED' : 'ADMITTED') ||
    after.state !== (enable ? 'ENABLED' : 'INSTALLED_DISABLED') ||
    before.revision !== context.expectedRevision ||
    BigInt(after.revision) !== BigInt(before.revision) + 1n ||
    BigInt(after.revision) > 18446744073709551615n ||
    before.moduleId !== after.moduleId ||
    before.semanticVersion !== after.semanticVersion ||
    before.generation !== '1' ||
    after.generation !== '1' ||
    before.active !== disable ||
    (enable || disable
      ? !Buffer.isBuffer(before.evaluationDigest) || before.evaluationDigest.length !== 32
      : before.evaluationDigest !== null && before.evaluationDigest !== undefined) ||
    (disable
      ? !before.activeManifestDigest?.equals(before.manifestDigest)
      : before.activeManifestDigest !== null) ||
    after.active !== enable ||
    !before.manifestDigest.equals(after.manifestDigest) ||
    !before.dependencyDigest.equals(after.dependencyDigest) ||
    !before.configurationDigest.equals(after.configurationDigest) ||
    !Buffer.isBuffer(after.evaluationDigest) ||
    after.evaluationDigest.length !== 32 ||
    (enable
      ? !after.activeManifestDigest?.equals(after.manifestDigest)
      : after.activeManifestDigest !== null)
  )
    throw new ContractError('PC-MODULE-7003');
  const bind = (state: AdmissionState) => {
    const projection = new Map<number, CborValue>([
      [0, state.moduleId],
      [1, state.semanticVersion],
      [2, state.manifestDigest],
      [3, state.dependencyDigest],
      [4, state.configurationDigest],
      [5, state.state],
      [6, state.activeManifestDigest === null ? 0n : 1n],
      [7, BigInt(state.generation)],
      [8, state.active ? 1n : 0n],
    ]);
    if (state.evaluationDigest) projection.set(9, state.evaluationDigest);
    if (state.activeManifestDigest) projection.set(10, state.activeManifestDigest);
    const revision = BigInt(state.revision);
    const preimage = transitionStatePreimage(
      {
        profileDigest: Buffer.from(profile.profileDigest.slice(7), 'hex'),
        participantId: context.authorization.participantId,
        privacyDomainId: context.authorization.privacyDomainId,
        aggregateType: profile.aggregateType,
        aggregateId: context.resourceId,
      },
      1,
      revision,
      projection,
    );
    return {
      preimage,
      reference: {
        existence: 1 as const,
        revision,
        stateDigest: createHash('sha256').update(preimage).digest(),
      },
    };
  };
  return { before: bind(before), after: bind(after) };
}
