export type RuleOperator =
  'EXISTS' | 'EQUALS' | 'NOT_EQUALS' | 'IN' | 'NOT_IN' | 'ARRAY_INTERSECTS' | 'STRING_CONTAINS_ANY';

export interface SelectionRule {
  field: string;
  operator: RuleOperator;
  value?: unknown;
}

export interface AssertionProfile {
  assertionProfileId: string;
  selectionRules: Array<{ all: SelectionRule[]; any: SelectionRule[]; inventory: string }>;
}

function valueAt(source: unknown, pointer: string): unknown {
  return pointer
    .split('/')
    .slice(1)
    .reduce<unknown>(
      (current, segment) =>
        typeof current === 'object' && current !== null
          ? (current as Record<string, unknown>)[segment]
          : undefined,
      source,
    );
}

function matches(rule: SelectionRule, source: unknown): boolean {
  const actual = valueAt(source, rule.field);
  switch (rule.operator) {
    case 'EXISTS':
      return actual !== undefined;
    case 'EQUALS':
      return actual === rule.value;
    case 'NOT_EQUALS':
      return actual !== rule.value;
    case 'IN':
      return Array.isArray(rule.value) && rule.value.includes(actual);
    case 'NOT_IN':
      return actual !== undefined && Array.isArray(rule.value) && !rule.value.includes(actual);
    case 'ARRAY_INTERSECTS':
      return (
        Array.isArray(actual) &&
        Array.isArray(rule.value) &&
        actual.some((item) => rule.value.includes(item))
      );
    case 'STRING_CONTAINS_ANY':
      return (
        typeof actual === 'string' &&
        Array.isArray(rule.value) &&
        rule.value.some((item) => actual.includes(String(item)))
      );
  }
}

/** Every matching profile is selected conjunctively. */
export function selectProfiles(
  profiles: AssertionProfile[],
  inventory: string,
  source: unknown,
): AssertionProfile[] {
  return profiles.filter((profile) =>
    profile.selectionRules.some(
      (selection) =>
        selection.inventory === inventory &&
        selection.all.every((rule) => matches(rule, source)) &&
        (selection.any.length === 0 || selection.any.some((rule) => matches(rule, source))),
    ),
  );
}
