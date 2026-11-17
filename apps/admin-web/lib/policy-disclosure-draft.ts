import { z } from 'zod';
import { reviewPolicyDocument } from './policy-document-review';

const uuid = z
  .string()
  .regex(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u);
const revision = z
  .string()
  .max(20)
  .regex(/^[1-9][0-9]*$/u)
  .refine((value) => value.length < 20 || value <= '18446744073709551615');
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const label = z
  .string()
  .min(1)
  .max(256)
  .regex(/^[!-~]+$/u)
  .refine((value) => !value.includes('*'));
const labels = z
  .array(label)
  .max(64)
  .refine((values) => new Set(values).size === values.length);
const selector = z.discriminatedUnion('kind', [
  z.strictObject({ kind: z.literal('STATE_READ'), contractMethodPolicyId: uuid, revision }),
  z.strictObject({
    kind: z.literal('EVENT'),
    runtimeBindingId: uuid,
    bindingRevision: revision,
    abiDigest: digest,
    eventSignature: label.refine((value) => value.includes('(') && value.endsWith(')')),
  }),
  z.strictObject({
    kind: z.enum(['TRANSACTION', 'RECEIPT']),
    runtimeBindingId: uuid,
    bindingRevision: revision,
  }),
  z.strictObject({
    kind: z.literal('DISCLOSURE'),
    profileId: uuid,
    profileDigest: digest,
    dataClassId: label,
  }),
]);
export const disclosureDimensionLabels = {
  EXISTENCE: 'Existence',
  METADATA: 'Metadata',
  PAYLOAD: 'Payload',
  EVIDENCE: 'Evidence',
  EXPORT: 'Export',
} as const;
export type DisclosureDimension = keyof typeof disclosureDimensionLabels;
const policy = z
  .strictObject({
    policyId: uuid,
    selector,
    mode: z.enum(['STATIC', 'DYNAMIC']),
    effect: z.enum(['ALLOW', 'DENY']),
    subject: z.discriminatedUnion('kind', [
      z.strictObject({ kind: z.literal('PRINCIPAL'), principalId: uuid }),
      z.strictObject({
        kind: z.literal('WORKLOAD'),
        workloadId: z
          .string()
          .regex(
            /^urn:openpc:workload:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
          ),
      }),
    ]),
    purpose: label,
    requiredRoles: labels,
    dimensions: z
      .array(z.enum(['EXISTENCE', 'METADATA', 'PAYLOAD', 'EVIDENCE', 'EXPORT']))
      .max(5)
      .refine((values) => new Set(values).size === values.length),
    fields: labels,
    conditions: z.array(z.record(z.string(), z.unknown())).max(16),
  })
  .refine(
    (rule) =>
      (rule.mode !== 'DYNAMIC' || rule.conditions.length > 0) &&
      (rule.selector.kind !== 'RECEIPT' || rule.fields.length === 0) &&
      (rule.effect !== 'ALLOW' ||
        (rule.requiredRoles.length > 0 &&
          rule.dimensions.length > 0 &&
          (rule.selector.kind === 'RECEIPT' ||
            !rule.dimensions.includes('PAYLOAD') ||
            rule.fields.length > 0))),
  );
export type DisclosureDraftRule = z.infer<typeof policy>;
type Scope = { participantId: string; privacyDomainId: string };
type Document = Record<string, unknown> & { visibilityPolicies?: Record<string, unknown>[] };

// Display and draft editing only. Native owners still admit resources, roles and Facts.
export function readDisclosureDraft(text: string, scope: Scope) {
  if ('error' in reviewPolicyDocument(text, scope)) return undefined;
  const document = JSON.parse(text) as Document;
  const result = z
    .array(policy)
    .max(256)
    .safeParse(document.visibilityPolicies ?? []);
  if (
    !result.success ||
    new Set(result.data.map((rule) => rule.policyId)).size !== result.data.length
  )
    return undefined;
  return { document, rules: result.data };
}
export type DisclosureDraftChange =
  { effect: 'ALLOW' | 'DENY' } | { dimensions: DisclosureDimension[] } | { fields: string[] };
const fixed = ({
  effect: _effect,
  dimensions: _dimensions,
  fields: _fields,
  ...value
}: DisclosureDraftRule) => value;

export function changeDisclosureDraft(
  text: string,
  original: string,
  scope: Scope,
  policyId: string,
  change: DisclosureDraftChange,
): { value: string } | { error: string } {
  if (
    !z
      .union([
        z.strictObject({ effect: z.enum(['ALLOW', 'DENY']) }),
        z.strictObject({
          dimensions: z.array(z.enum(['EXISTENCE', 'METADATA', 'PAYLOAD', 'EVIDENCE', 'EXPORT'])),
        }),
        z.strictObject({ fields: z.array(z.string()) }),
      ])
      .safeParse(change).success
  )
    return { error: 'Change one response permission at a time.' };
  const current = readDisclosureDraft(text, scope),
    base = readDisclosureDraft(original, scope);
  const rule = current?.rules.find((rule) => rule.policyId === policyId),
    source = base?.rules.find((rule) => rule.policyId === policyId);
  if (!current || !rule || !source || JSON.stringify(fixed(rule)) !== JSON.stringify(fixed(source)))
    return { error: 'Reload this policy file before changing its disclosure rules.' };
  const next = policy.safeParse({ ...rule, ...change });
  if (!next.success)
    return {
      error:
        'Allowing disclosure requires roles and at least one dimension. Payload also requires a selected field, except for a whole receipt.',
    };
  if (
    next.data.dimensions.some((value) => !source.dimensions.includes(value)) ||
    next.data.fields.some((value) => !source.fields.includes(value))
  )
    return { error: 'Select only dimensions and fields present in the imported rule.' };
  const rules = current.document.visibilityPolicies!;
  const index = current.rules.findIndex((value) => value.policyId === policyId);
  rules[index] = { ...rules[index], ...change };
  const value = JSON.stringify(current.document, null, 2);
  const reviewed = reviewPolicyDocument(value, scope);
  return 'error' in reviewed ? { error: reviewed.error } : { value };
}
