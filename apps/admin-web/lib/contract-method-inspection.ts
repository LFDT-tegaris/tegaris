import { z } from 'zod';
import type { PolicyWorkflowActorBinding } from '../components/policy-workflow-storage';

const uuid = z.uuid();
const reference = z.string().regex(/^urn:openpc:resource:[0-9a-f-]{36}$/u);
const revision = z.string().regex(/^[1-9][0-9]*$/u);
const actor = z.object({
  sessionId: uuid,
  principalId: uuid,
  participantId: uuid,
  privacyDomainId: uuid,
  contextEpoch: z.string().min(1),
});

/** Browser-safe display projection; enforcement stays with the public owners. */
export const contractMethodInspectionSchema = z.strictObject({
  actor,
  method: z.object({
    contractMethodPolicyId: reference,
    runtimeBindingId: reference,
    abiArtifactId: reference,
    canonicalSignature: z.string().min(1),
    selector: z.string().regex(/^0x[0-9a-f]{8}$/u),
    effect: z.enum(['READ', 'WRITE']),
    requiredRoles: z.array(z.string()),
    approvalRequirement: z.enum(['NONE', 'SINGLE', 'MAKER_CHECKER']),
    mfaRequirement: z.enum(['NONE', 'WEBAUTHN']),
    environments: z.array(z.string()),
    argumentRuleVersionId: reference.nullable(),
    state: z.enum(['PREPARED', 'ACTIVE', 'RETIRED', 'QUARANTINED']),
    revision,
  }),
  binding: z.object({
    runtimeBindingId: reference,
    logicalContractId: reference,
    abiArtifactId: reference,
    contractAddress: z.string().regex(/^0x[0-9a-fA-F]{40}$/u),
    chainId: z.string(),
    networkId: z.string(),
    state: z.enum(['BOUND', 'QUARANTINED', 'RETIRED']),
    revision,
  }),
  contract: z.object({
    logicalContractId: reference,
    logicalName: z.string(),
    displayName: z.string(),
    revision,
  }),
  argumentRules: z
    .object({
      argumentRuleVersionId: reference,
      runtimeBindingId: reference,
      abiArtifactId: reference,
      canonicalSignature: z.string(),
      version: z.string(),
      state: z.enum(['PREPARED', 'ACTIVE', 'RETIRED']),
      revision,
      rules: z.array(
        z.object({
          parameterPath: z.string(),
          operandType: z.string(),
          operator: z.string(),
          // Integer operands are canonical strings; never coerce them to Number.
          values: z.array(z.string()),
        }),
      ),
    })
    .nullable(),
});
export type ContractMethodInspection = z.infer<typeof contractMethodInspectionSchema>;

export function methodPolicyReference(value: string): string | undefined {
  if (uuid.safeParse(value).success) return `urn:openpc:resource:${value}`;
  if (reference.safeParse(value).success && uuid.safeParse(value.slice(-36)).success) return value;
  return undefined;
}

export function inspectionActorKey(value: PolicyWorkflowActorBinding): string {
  return [
    value.sessionId,
    value.principalId,
    value.participantId,
    value.privacyDomainId,
    value.contextEpoch,
  ].join(':');
}

export function inspectionReferencesMatch(view: ContractMethodInspection): boolean {
  const { method, binding, contract, argumentRules } = view;
  return (
    method.runtimeBindingId === binding.runtimeBindingId &&
    method.abiArtifactId === binding.abiArtifactId &&
    binding.logicalContractId === contract.logicalContractId &&
    (argumentRules === null
      ? method.argumentRuleVersionId === null
      : method.argumentRuleVersionId === argumentRules.argumentRuleVersionId &&
        method.runtimeBindingId === argumentRules.runtimeBindingId &&
        method.abiArtifactId === argumentRules.abiArtifactId &&
        method.canonicalSignature === argumentRules.canonicalSignature)
  );
}
