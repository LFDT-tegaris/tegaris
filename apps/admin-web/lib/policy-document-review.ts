export const policyDocumentMaximumBytes = 1_048_576;

type Scope = { participantId: string; privacyDomainId: string };
type ObjectValue = Record<string, unknown>;
const object = (value: unknown): value is ObjectValue =>
  !!value && typeof value === 'object' && !Array.isArray(value);
const requiredLists = [
  'moduleBindings',
  'rpcPolicies',
  'contractPolicies',
  'requiredFacts',
] as const;
const optionalLists = [
  'visibilityPolicies',
  'deploymentPolicies',
  'indexerPolicies',
  'factConditions',
] as const;
const keys = new Set<string>([
  'schemaVersion',
  'participantId',
  'privacyDomainId',
  ...requiredLists,
  ...optionalLists,
]);

export type PolicyDocumentReview =
  | { error: string }
  | {
      counts: { label: string; count: number }[];
      rpcRules: { method: string; effect: 'ALLOW' | 'DENY' }[];
      rpcRuleCount: number;
    };

// This is a bounded draft review, never semantic admission or authority.
// The native compiler still validates every dependency, rule and reference.
export function reviewPolicyDocument(text: string, scope: Scope): PolicyDocumentReview {
  if (!text.trim()) return { error: 'Choose a policy file to review its contents.' };
  if (new TextEncoder().encode(text).byteLength > policyDocumentMaximumBytes)
    return { error: 'The policy file must be no larger than 1 MiB.' };
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return { error: 'Use a valid JSON policy file.' };
  }
  if (
    !object(value) ||
    Object.keys(value).some((key) => !keys.has(key)) ||
    value.schemaVersion !== '1.0.0'
  )
    return { error: 'Use a supported policy document without configuration or credential fields.' };
  if (
    value.participantId !== scope.participantId ||
    value.privacyDomainId !== scope.privacyDomainId
  )
    return { error: 'This policy file belongs to a different workspace.' };
  if (
    requiredLists.some((key) => !Array.isArray(value[key])) ||
    optionalLists.some((key) => value[key] !== undefined && !Array.isArray(value[key]))
  )
    return { error: 'The policy document must include its rule and dependency lists.' };
  const lists = [...requiredLists, ...optionalLists];
  if (
    lists.some(
      (key) => Array.isArray(value[key]) && (value[key] as unknown[]).some((item) => !object(item)),
    )
  )
    return { error: 'The policy document contains an unreadable rule or dependency.' };
  const rpcRules: { method: string; effect: 'ALLOW' | 'DENY' }[] = [];
  for (const policy of value.rpcPolicies as ObjectValue[]) {
    if (
      policy.schemaVersion !== '1.0.0' ||
      policy.participantId !== scope.participantId ||
      policy.privacyDomainId !== scope.privacyDomainId ||
      !Array.isArray(policy.rules)
    )
      return { error: 'The RPC rules must belong to the current workspace.' };
    for (const rule of policy.rules) {
      if (
        !object(rule) ||
        typeof rule.method !== 'string' ||
        rule.method.length === 0 ||
        rule.method.length > 128 ||
        !['ALLOW', 'DENY'].includes(String(rule.effect))
      )
        return { error: 'The RPC rule list could not be reviewed.' };
      rpcRules.push({ method: rule.method, effect: rule.effect as 'ALLOW' | 'DENY' });
    }
  }
  const labels: Record<(typeof lists)[number], string> = {
    moduleBindings: 'Module dependencies',
    rpcPolicies: 'RPC policy groups',
    contractPolicies: 'Contract method policies',
    requiredFacts: 'Required facts',
    visibilityPolicies: 'Disclosure rules',
    deploymentPolicies: 'Deployment policies',
    indexerPolicies: 'Source policies',
    factConditions: 'Fact conditions',
  };
  return {
    counts: lists.map((key) => ({
      label: labels[key],
      count: (value[key] as unknown[] | undefined)?.length ?? 0,
    })),
    rpcRules: rpcRules.slice(0, 12),
    rpcRuleCount: rpcRules.length,
  };
}
