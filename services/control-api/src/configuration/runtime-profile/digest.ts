import { sha256 } from '../digest.js';

/** Identity and runtime use the same closed scope tuple. A digest identifies
 * the governed mapping; it does not grant any workload access. */
export function runtimeTargetProfileBindingDigest(scope: {
  participantId: string;
  privacyDomainId: string;
  targetRuntimeId: string;
  targetProfileId: string;
}): string {
  return sha256({
    purpose: 'openpc.identity.runtime-target-profile-binding.v1',
    participant_id: scope.participantId,
    privacy_domain_id: scope.privacyDomainId,
    runtime_target_id: scope.targetRuntimeId,
    target_profile_id: scope.targetProfileId,
  });
}
