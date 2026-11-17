import { businessTransitionProfiles } from './profiles.generated.js';

export type BusinessTransitionProfile = (typeof businessTransitionProfiles)[number];
for (const profile of businessTransitionProfiles) Object.freeze(profile);
Object.freeze(businessTransitionProfiles);

/** Only the generated, explicitly admitted profile list can select an aggregate namespace. */
export function businessTransitionProfileForOperation(
  operationId: string,
  version = 1,
): BusinessTransitionProfile | undefined {
  return businessTransitionProfiles.find(
    (profile) => profile.catalogOperationId === operationId && profile.profileVersion === version,
  );
}
