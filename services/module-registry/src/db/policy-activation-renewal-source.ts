import {
  policyActivationRenewalSourceSchema,
  type PolicyActivationRenewalSource,
  type RenewPolicyActivation,
} from '../policy-activation-renewal-contract.js';
import { canonicalJson } from '../domain/digest.js';
import { ContractError } from '../domain/errors.js';

/** A reconnect may advance an untouched initial target. Fresh approval still
 * binds its current revision; the original occurrence snapshot stays intact. */
export function policyRenewalTargetRevisionMatches(
  initialPrepared: boolean,
  originalRevision: string,
  current: Readonly<{
    revision: string;
    state: string;
    requiresAuthenticatedDiscovery?: boolean;
    activeGenerationDigest: string | null;
    desiredGenerationDigest: string | null;
    policyGenerationDigest: string | null;
  }>,
): boolean {
  if (originalRevision === current.revision) return true;
  return (
    initialPrepared &&
    BigInt(current.revision) > BigInt(originalRevision) &&
    current.requiresAuthenticatedDiscovery === true &&
    current.state === 'DISCOVERED' &&
    current.activeGenerationDigest === null &&
    current.desiredGenerationDigest === null &&
    current.policyGenerationDigest === null
  );
}

export function assertPolicyRenewalSource(
  input: RenewPolicyActivation,
  current: PolicyActivationRenewalSource,
): void {
  const commandFields = new Set(['command', 'actionIntentId', 'actionIntentDigest', 'reason']);
  const source = Object.fromEntries(
    Object.entries(input).filter(([key]) => !commandFields.has(key)),
  );
  const parsed = policyActivationRenewalSourceSchema.safeParse(source);
  if (!parsed.success || canonicalJson(parsed.data) !== canonicalJson(current))
    throw new ContractError('PC-POLICY-2003');
}
