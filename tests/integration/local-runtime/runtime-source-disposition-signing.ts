import assert from 'node:assert/strict';
import { businessTransitionProfiles } from '../../../packages/security-kernel/src/business-transition/profiles.generated.js';

// Initial local fixture trust only. Each family owns a separate immutable key;
// an existing selected key is never extended or replaced by this bootstrap.
export const runtimeSourceSigningFamilies = Object.freeze([
  {
    family: 'retention',
    profileIds: ['pc.control.retention-policy.activate', 'pc.control.retention-policy.retire'],
  },
  { family: 'disposition', profileIds: ['pc.control.runtime-artifact.disposition'] },
  { family: 'retirement', profileIds: ['pc.control.evidence-deletion.runtime-artifact'] },
]);
export function runtimeSourceSigningProfiles(family: string) {
  const definition = runtimeSourceSigningFamilies.find((item) => item.family === family);
  assert.ok(definition, 'Exact runtime source signing family required');
  return definition.profileIds.map((id) => {
    const found = businessTransitionProfiles.filter(
      (profile) => profile.profileId === id && profile.profileVersion === 1,
    );
    assert.equal(found.length, 1);
    return found[0]!;
  });
}
export function runtimeSourceSigningName(privacy: string, family: string) {
  runtimeSourceSigningProfiles(family);
  assert.match(privacy, /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u);
  return `control_runtime_source_${privacy}_${family}_signing`;
}
