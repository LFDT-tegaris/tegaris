import { preparedBusinessTransitionProfiles } from './profiles.prepared.generated.js';

export type PreparedBusinessTransitionProfile = (typeof preparedBusinessTransitionProfiles)[number];
for (const profile of preparedBusinessTransitionProfiles) Object.freeze(profile);
Object.freeze(preparedBusinessTransitionProfiles);

/** PASSIVE source-contract projection only. Never use this lookup to select a
 * namespace, admit a signer/receipt, generate SQL grants or authorize an effect.
 * Installed owners use the separate admitted businessTransitionProfileForOperation. */
export function preparedBusinessTransitionProfileForOperation(
  operationId: string,
  version = 1,
): PreparedBusinessTransitionProfile | undefined {
  return preparedBusinessTransitionProfiles.find(
    (profile) => profile.catalogOperationId === operationId && profile.profileVersion === version,
  );
}
